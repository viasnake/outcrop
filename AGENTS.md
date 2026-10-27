# Repository Agent Guidance

## UI and UX

- Make the interface understandable through its controls, labels, states, and
  interactions. Improve the UI or workflow when it needs explanatory prose to
  be understood.
- Do not add user-facing prose that narrates background processing or internal
  mechanisms, such as automatic refresh, worker scheduling, or cache retrieval.
  Remove such explanations when editing existing screens.
- Keep concise action results, actionable errors, and information needed for a
  decision, such as why a disk cannot be selected or whether it is safe to
  disconnect. Do not hide useful diagnostics to reduce text.
- Keep implementation and operational explanations in the appropriate developer
  or operator documentation rather than in product screens.
