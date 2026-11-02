"""Opt-in argparse routing to existing phases; ordinary arguments are unchanged."""
import argparse

PHASES = {'brokered_http_plan': 'controlled_validation_plane',
          'strict_replay_plan': 'controlled_validation_plane',
          'llm_security_input': 'ai_llm_tooling', 'learning_corpus_input': 'ai_llm_tooling',
          'delivery_audit_input': 'engagement_evidence_review'}
LOCAL_LABEL = 'local-analysis.invalid'


class CapabilityInput(argparse.Action):
    def __init__(self, *args, phase_order, **kwargs):
        self.phase_order = phase_order
        super().__init__(*args, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, values)
        current = getattr(namespace, 'phases', None)
        previous = getattr(namespace, '_research_last_auto_phases', None)
        explicit = bool(current) and current != previous
        wanted = set(getattr(namespace, '_research_requested_phases', []))
        wanted.add(PHASES[self.dest])
        namespace._research_requested_phases = sorted(wanted)
        if not explicit:
            wanted.update({'preflight', 'report', 'evidence_finalize'})
            namespace.phases = ','.join(phase for phase in self.phase_order if phase in wanted)
            namespace._research_last_auto_phases = namespace.phases
        if self.dest in {'brokered_http_plan', 'strict_replay_plan'}:
            if getattr(namespace, '_research_auto_domain', False) and namespace.domain == LOCAL_LABEL:
                namespace.domain = None
            namespace._research_requires_target = True
        elif not getattr(namespace, '_research_requires_target', False) and not any(
                getattr(namespace, key, None) for key in ('domain', 'url', 'list', 'urls')):
            namespace.domain = LOCAL_LABEL
            namespace._research_auto_domain = True
