import yaml

from core.checks import CallbackHelper
from core.searchtools import FileSearcher
from core.analytics import LogEventStats, SearchResultIndices
from core import checks, utils
from core.plugins.openstack import (
    OpenstackChecksBase,
    OpenstackEventChecksBase,
)

YAML_PRIORITY = 9
EVENTCALLBACKS = CallbackHelper()


class NeutronAgentEventChecks(OpenstackEventChecksBase):
    """
    Loads events we want to check from definitions yaml and executes them. The
    results are sorted by date and the "top 5" are presented along with stats
    on the full set of samples.
    """

    def process_results(self, results):
        """ See defs/events.yaml for definitions. """
        agent_info = {}
        for section, events in self.event_definitions.items():
            agent_name = section
            for event in events:
                sri = None
                # TODO: find a way to get rid of the need to provide this
                if event == "router-updates":
                    sri = SearchResultIndices(event_id_idx=4,
                                              metadata_idx=3,
                                              metadata_key="router")

                stats = LogEventStats(results, event, custom_idxs=sri)
                stats.run()
                top5 = stats.get_top_n_events_sorted(5)
                if not top5:
                    break

                info = {"top": top5,
                        "stats": stats.get_event_stats()}
                if agent_name not in agent_info:
                    agent_info[agent_name] = {}

                agent_info[agent_name][event] = info

        return agent_info


class NeutronAgentBugChecks(checks.BugChecksBase):
    """ See defs/bugs.yaml for definitions. """


class OctaviaAgentEventChecks(OpenstackEventChecksBase):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, callback_helper=EVENTCALLBACKS,
                         event_results_output_key='octavia', **kwargs)

    def _get_failover(self, result):
        ts_date = result.get(1)
        payload = yaml.safe_load(result.get(2))
        lb_id = payload.get("load_balancer_id")
        if lb_id is None:
            return None, None

        return ts_date, lb_id

    def _get_failovers(self, results):
        failovers = {}
        for r in results:
            ts_date, lb_id = self._get_failover(r)
            if ts_date is None:
                continue

            if ts_date not in failovers:
                failovers[ts_date] = {}

            if lb_id not in failovers[ts_date]:
                failovers[ts_date][lb_id] = 1
            else:
                failovers[ts_date][lb_id] += 1

        return failovers

    @EVENTCALLBACKS.callback
    def lb_failover_auto(self, event):
        results = event['results']
        if not results:
            return

        ret = self._get_failovers(results)
        if ret:
            return {'auto': ret}, 'lb-failovers'

    @EVENTCALLBACKS.callback
    def lb_failover_manual(self, event):
        results = event['results']
        if not results:
            return

        ret = self._get_failovers(results)
        if ret:
            return {'manual': ret}, 'lb-failovers'

    @EVENTCALLBACKS.callback
    def amp_missed_heartbeats(self, event):
        results = event['results']
        if not results:
            return

        missed_heartbeats = {}
        for r in results:
            ts_date = r.get(1)
            amp_id = r.get(2)

            if ts_date not in missed_heartbeats:
                missed_heartbeats[ts_date] = {}

            if amp_id not in missed_heartbeats[ts_date]:
                missed_heartbeats[ts_date][amp_id] = 1
            else:
                missed_heartbeats[ts_date][amp_id] += 1

        # sort each amp by occurences
        for ts_date, amps in missed_heartbeats.items():
            missed_heartbeats[ts_date] = utils.sorted_dict(amps,
                                                           key=lambda e: e[1],
                                                           reverse=True)

        if not missed_heartbeats:
            return

        # then sort by date
        return utils.sorted_dict(missed_heartbeats)


class AgentApparmorChecks(OpenstackEventChecksBase):

    def process_results(self, results):
        """ See defs/events.yaml for definitions. """
        info = {}
        for section, events in self.event_definitions.items():
            aa_action = section
            for event in events:
                _results = results.find_by_tag(event)
                for r in _results:
                    ts = r.get(1)
                    profile = r.get(2)
                    if aa_action not in info:
                        info[aa_action] = {}

                    if event not in info[aa_action]:
                        info[aa_action][event] = {}

                    if ts not in info[aa_action][event]:
                        info[aa_action][event][ts] = {}

                    if profile not in info[aa_action][event][ts]:
                        info[aa_action][event][ts][profile] = 1
                    else:
                        info[aa_action][event][ts][profile] += 1

        if info:
            return {"apparmor": info}


class AgentChecks(OpenstackChecksBase):

    def __call__(self):
        # Only run if we think Openstack is installed.
        if not self.openstack_installed:
            return

        s = FileSearcher()
        checks = [NeutronAgentEventChecks("neutron-agent-checks", searchobj=s),
                  NeutronAgentBugChecks("neutron", searchobj=s),
                  OctaviaAgentEventChecks("octavia-checks", searchobj=s),
                  AgentApparmorChecks("apparmor-checks", searchobj=s)]
        for check in checks:
            check.register_search_terms()

        results = s.search()
        output = {}
        for check in checks:
            check_results = check.process_results(results)
            if check_results:
                output.update(check_results)

        if output:
            self._output = {"agent-checks": output}
