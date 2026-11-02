# TBHM v4.2.5 — Advanced Security Research, Continuous Learning, Self-Evaluation & Verified Improvement

## YOUR ROLE

You are the Principal Security Tool Architect, Senior Python Engineer, Application Security Researcher, Machine Learning Engineer, LLM Evaluation Specialist, DevSecOps Engineer, and Release QA Lead responsible for continuing the development of TBHM.

You are working on an existing security assessment platform.

**CURRENT BASELINE: TBHM v4.2.4**

**TARGET RELEASE: TBHM v4.2.5**

This is a REAL SOFTWARE DEVELOPMENT AND IMPLEMENTATION TASK.

Your responsibilities include inspecting, fixing, extending, testing, benchmarking, and packaging the existing tool.

Do not replace the current project.

Do not create a superficial wrapper around other security tools.

Do not stop at research, recommendations, pseudocode, or documentation.

Do not claim a feature is implemented unless real executable code, integration tests, and supporting evidence exist.

Your primary mission is to transform TBHM into a more capable, accurate, resource-efficient and evidence-driven security research platform with a persistent learning system that improves from past and future authorized testing scenarios.

The system must become better through measurable experience, not through unverified AI assumptions.

---

# PART 1 — UNDERSTAND AND PRESERVE THE EXISTING SYSTEM

## 1.1 Mandatory Repository Audit

Before implementing changes, completely inspect the available v4.2.4 source tree and related research artifacts.

Review:

- Existing 145 phases and dispatch ordering.
- Existing 463 CLI argument signatures.
- Core controller and Runner/Ctx.
- Proof-v2 contracts.
- Assertion engine and finding classification.
- Strict replay workflows.
- Pinned HTTP transport.
- Scope, rate, cooldown and offline gates.
- Evidence receipts and sealed deliveries.
- SQLite persistence.
- Security scanner adapters.
- Source-code analysis.
- API authorization workflows.
- Reporting.
- Existing local LLM integrations.
- Existing learning and memory components.
- Existing test and evaluation infrastructure.

Specifically inspect:

- `core/proof_contracts.py`
- `core/assertion_engine.py`
- `core/finding_class.py`
- `core/strict_classes_v424.py`
- `core/pinned_transport.py`
- `core/quality_evaluation.py`
- `core/ai_plane/run_learning.py`
- `core/ai_plane/observer.py`
- `core/ai_plane/advisor.py`
- `core/ai_plane/proposals.py`
- `core/ai_plane/store.py`
- `core/ai_plane/embeddings.py`
- `core/llm_local.py`
- `core/llm_review.py`
- `core/learning_corpus_audit.py`
- `core/llm_security_import.py`

Identify all existing functionality before deciding whether to add, modify, reuse or remove internal duplication.

Preserve existing interfaces wherever possible.

## 1.2 Flow Preservation Contract

Preserve all existing v4.2.4 phase names, ordinals and valid behaviors.

Any new phase must be appended after the original sequence.

Existing CLI actions and argument meanings must remain compatible.

SQLite changes must use additive, versioned migrations with rollback and preservation tests.

The proof modules are allowed to evolve.

Do not SHA256-freeze source files that require development.

Use behavioral regression tests instead.

Do not weaken existing proof rules to obtain more confirmed findings.

Permit narrowly scoped corrections to demonstrated defects only with failing-before/passing-after regression evidence.

Preserve the intentional security fixes introduced in v4.2.1 through v4.2.4.

New functionality must not bypass:

- Authorized target scope.
- Request budgets.
- Rate limits.
- Cooldowns.
- Offline enforcement.
- Credential isolation.
- Evidence integrity.
- Proof-v2.
- Human approval requirements.

Never introduce a hidden alternative execution path.

---

# PART 2 — FIX CURRENT v4.2.4 LIMITATIONS

## 2.1 Runtime and Network Containment

The current pinned transport is useful but does not provide universal containment of all legacy scanners, browsers and child processes.

Inspect every actual network execution path.

Improve enforcement for:

- Native HTTP requests.
- HTTP replay.
- Child processes.
- External scanners.
- Browser automation.
- Proxy adapters.
- Redirect handling.
- DNS resolution.
- Concurrent network activity.

Implement centralized scope, rate, request and response-budget enforcement where technically feasible.

Preserve original hostname, TLS certificate and SNI validation when connecting through pinned addresses.

Prevent unexpected cross-origin requests and DNS-rebinding bypasses.

Unsupported scanner transport must fail closed when containment is mandatory.

Maintain honest distinctions between:

- Accepted decoded bytes.
- HTTP request accounting.
- Transfer bytes.
- True on-wire bytes.
- Traffic originating outside the broker.

Do not claim global wire metering unless it is genuinely implemented and validated across all advertised execution paths.

Develop isolated network integration tests and OS-level egress tests.

Never weaken a security gate merely to make a scanner adapter work.

## 2.2 Evidence and Privacy Closure

Audit every evidence producer and artifact writer.

Review:

- JSON and JSONL.
- Markdown and HTML.
- CSV and SARIF.
- SQLite.
- Scanner output.
- Logs.
- Temporary artifacts.
- Archives.
- Supported compressed formats.
- PDFs.
- Binary artifacts.
- LLM prompt contexts.
- Exported training datasets.

Expand sensitive-data detection, bounded parsing and privacy review.

Preserve original evidence separately from sanitized exports.

Make incomplete audits explicit.

Signed evidence requiring modification must block unsafe delivery rather than being silently rewritten.

Ensure sensitive data cannot be introduced into LLM training or persistent memory without an approved processing path.

## 2.3 Strict Proof Engine Expansion

Preserve the current verified classes:

- access_control
- sensitive_data_exposure
- open_redirect
- path_traversal
- bfla

Evaluate and implement safe, class-specific verification contracts for additional vulnerabilities, prioritizing:

1. SQL injection.
2. XSS variants.
3. SSRF.
4. SSTI.
5. Authentication and session failures.
6. CSRF.
7. Unsafe deserialization.
8. Additional authorization and tenant-isolation failures.

Each verifier requires:

- Explicit preconditions.
- Scoped, authorized test targets.
- Positive evidence.
- Negative controls.
- Benign controls.
- Repetition.
- Tamper resistance.
- False-correlation checks.
- Inconclusive handling.
- Proof receipt.
- Reproducible test fixtures.

Use non-destructive tests by default.

Do not confirm issues from status codes, reflections, scanner alerts or model opinions alone.

For BFLA and traversal, improve proof generalization without weakening the need for credible ownership, authorization and filesystem evidence.

A fixture-specific verifier must not be advertised as a universal verifier.

Do not add incomplete verifiers merely to increase the number of supported classes.

---

# PART 3 — BUILD THE TBHM CONTINUOUS LEARNING ENGINE

## 3.1 Primary Objective

Create a persistent learning architecture that allows TBHM to improve its security research assistance using past and future authorized testing scenarios.

The learning engine must understand:

- What was tested.
- Why the test was selected.
- Which evidence was produced.
- What vulnerability was suspected.
- Whether the result was confirmed, refuted or inconclusive.
- Why a result was a false positive.
- What useful controls were missing.
- Which validation steps worked.
- Which approaches failed.
- Which fixes or adjustments were effective.
- Which limitations remain unresolved.

Do not confuse storing logs with successful learning.

Implement a measurable feedback loop.

## 3.2 Reuse Existing Learning Components

TBHM already includes run-artifact ingestion, mistake tracking, retrieval and proposal generation.

Inspect those implementations and extend them.

Do not recreate equivalent functionality under a competing architecture.

Preserve existing data and its provenance.

Extend the current system into five cooperating layers:

### Layer A — Scenario Memory

Persistent, structured memory of security testing cases.

### Layer B — Evidence Retrieval

Search and retrieve relevant prior cases and verified knowledge.

### Layer C — Reasoning and Recommendation

Use the LLM to analyze evidence and recommend better validation approaches.

### Layer D — Self-Evaluation

Measure recommendation quality against independently established outcomes.

### Layer E — Controlled Improvement

Generate and test candidate changes, promote only approved and validated improvements, and support rollback.

These layers must be independently testable.

---

# PART 4 — SCENARIO MEMORY DATABASE

## 4.1 Scenario Record Structure

Every eligible security testing scenario should have a structured, versioned record.

Include fields such as:

- scenario_id
- run_id
- project_id
- target_category
- test_environment
- scope_reference
- vulnerability_class
- CWE mapping
- relevant OWASP mapping
- affected component
- entry point
- prerequisites
- test objective
- observation summary
- sanitized evidence references
- evidence hashes
- negative-control references
- verification method
- proof status
- technical validity
- reviewer decision
- false-positive reason
- missed-detection reason
- root-cause category
- safe reproduction reference
- remediation summary
- model recommendation
- model confidence or uncertainty
- actual reviewer outcome
- program disposition, if available
- scenario timestamp
- tool version
- model version
- retrieval version
- data sensitivity
- reuse permission
- source license or lawful processing basis
- dataset split
- retention and revocation status

Use an additive schema compatible with existing persistence.

Do not store raw credentials, session cookies, private access tokens or unnecessary personal information in learning records.

## 4.2 Scenario Sources

Support authorized, reviewable ingestion from:

- Previous TBHM runs.
- Current TBHM runs.
- Existing run artifacts.
- Human-verified findings.
- False-positive reviews.
- Refuted findings.
- Inconclusive investigations.
- Approved pentest laboratory results.
- Authorized CTF/lab writeups.
- PortSwigger Academy exercises.
- OWASP testing labs.
- Locally owned vulnerable applications.
- Approved source-code review cases.
- Mobile and firmware analysis cases.
- Manually reviewed bug bounty outcomes.
- Public security research with suitable reuse rights.

Support future import of operator-authored writeups and structured research notes.

Never scrape or ingest private program data automatically.

Never assume that access to a report implies permission to train on it.

Distinguish observed technical validity from external program outcomes such as accepted, duplicate, informative, rejected or pending.

Those labels are not interchangeable.

## 4.3 Learning From Mistakes

When a scenario is reviewed, identify potential mistake categories:

- False-positive scanner signature.
- Incorrect source-to-sink interpretation.
- Missing authorization context.
- Inadequate negative controls.
- Unreliable timing evidence.
- Authentication/session expiry.
- Invalid object-ownership assumption.
- Out-of-scope request.
- Insufficient evidence.
- Incorrect vulnerability classification.
- Duplicate finding.
- Tool execution failure.
- Model hallucination.
- Incorrect retrieval.
- Dataset contamination.
- Unsupported environmental assumption.

Store reviewed explanations and associate them with relevant future scenarios.

In subsequent runs, use these records to help avoid repeating known mistakes.

However, a past failure must not automatically suppress a genuinely new finding.

Learning should improve prioritization and evidence requirements, not replace independent verification.

---

# PART 5 — RETRIEVAL-AUGMENTED SECURITY REASONING

## 5.1 Persistent Security Knowledge

Create or improve the existing evidence-grounded retrieval layer.

Maintain a versioned knowledge base covering:

- Vulnerability explanations.
- CWE relationships.
- OWASP testing references.
- Authentication and authorization patterns.
- Vulnerability-specific proof criteria.
- Safe source-to-sink examples.
- Previously reviewed scenarios.
- Known false-positive patterns.
- Root-cause explanations.
- Verification failures.
- Remediation guidance.
- Approved research material.

Each knowledge item must retain provenance and review state.

## 5.2 Scenario-Aware Retrieval

When evaluating a new finding, retrieve relevant historical cases using:

- Vulnerability class.
- Technology stack.
- Input or sink type.
- Authentication context.
- Dataflow pattern.
- Control failure.
- Similar evidence.
- Root cause.
- Relevant framework or component.
- Prior model mistakes.

Prefer well-supported reviewed cases over weak similarity matches.

Use a bounded retrieval budget.

Never include raw private secrets in the model context.

Treat retrieved content as untrusted data rather than instructions.

Prevent one project's private information from leaking into another project's model context.

## 5.3 Evidence-Based Reasoning

Require the LLM to answer:

1. What was observed?
2. Which evidence IDs support it?
3. What is still unproven?
4. What benign explanation is possible?
5. Which negative control is missing?
6. Which safe verification step would reduce uncertainty?
7. Which historical scenario is genuinely relevant?
8. What would falsify the hypothesis?

The model must distinguish:

- Observation.
- Hypothesis.
- Verified evidence.
- Inference.
- Confirmed vulnerability.
- Inconclusive outcome.

Never allow retrieved examples to create a false proof receipt.

---

# PART 6 — LLM SELF-EVALUATION

## 6.1 Build a Real Evaluation Engine

After an authorized run, generate a structured evaluation of the LLM's recommendations.

Compare the model's earlier predictions with later independent ground truth.

Track:

- Correct vulnerability classification.
- Incorrect vulnerability classification.
- Correct evidence references.
- Fabricated evidence references.
- Correctly identified missing controls.
- Incorrectly dismissed real vulnerabilities.
- False-positive recommendations.
- False-negative cases.
- Inconclusive decisions.
- Duplicate detection performance.
- Recommended validation usefulness.
- Prompt-injection resistance.
- Retrieval relevance.
- Resource consumption.
- Latency.
- Stability.

A model should not be allowed to grade its own correctness using only its own explanations.

Use deterministic validation and independent labels wherever possible.

## 6.2 Learning Evaluation Metrics

Measure at least:

- TP
- FP
- TN
- FN
- Inconclusive count
- Precision
- Recall
- False-positive rate
- False-negative rate
- Coverage
- Evidence citation validity
- Abstention rate
- Calibration
- Model latency
- Peak RAM/VRAM

Keep vulnerability discovery metrics separate from proof-verification metrics.

Preserve full-denominator and conditional metrics.

Report sample sizes and meaningful confidence intervals.

Do not extrapolate general performance from a few synthetic cases.

## 6.3 Independent Evaluation Sets

Create separate datasets for:

- Training.
- Validation.
- Held-out testing.
- Regression.
- Adversarial evaluation.

Prevent leakage between splits by checking:

- Project identity.
- Root-cause identity.
- Near-duplicate content.
- Shared fixtures.
- Versioned variants.
- Reused source-code fragments.

Freeze held-out test datasets before tuning.

Do not train on the held-out set after seeing its results.

When appropriate, use new projects and future-time scenarios to assess generalization.

## 6.4 Evaluation Reports

Produce a human-readable and machine-readable evaluation report containing:

- Model version.
- Dataset version.
- Retrieval configuration.
- Baseline metrics.
- Candidate metrics.
- Per-class performance.
- New improvements.
- Regressions.
- Failure examples.
- Unknowns.
- Resource measurements.
- Recommended next experiments.

Do not convert evaluation percentages into unsupported claims of universal security accuracy.

---

# PART 7 — AUTOMATED IMPROVEMENT LOOP

## 7.1 Controlled Self-Improvement

Implement the following process:

**OBSERVE → RECORD → REVIEW → RETRIEVE → HYPOTHESIZE → EVALUATE → PROPOSE → TEST → APPROVE → PROMOTE**

The system should identify recurring limitations and propose measurable improvements.

Candidate improvements may include:

- Better retrieval ranking.
- Improved evidence summarization.
- More accurate model instructions.
- Improved finding deduplication.
- Better uncertainty handling.
- New negative-control fixtures.
- Improved scanner result normalization.
- Better vulnerability classification rules.
- More efficient task scheduling.
- Improved report explanations.
- Additional verified proof contracts.
- Performance optimizations.

Each proposal must contain:

- Identified problem.
- Supporting scenario IDs.
- Supporting evidence IDs.
- Root-cause hypothesis.
- Proposed change.
- Affected files or configuration.
- Expected benefit.
- Risks.
- Regression tests.
- Success criteria.
- Rollback plan.

## 7.2 Safe Experimentation

The model may create candidate improvement proposals and patches.

It may evaluate isolated prompt, retrieval and analysis configurations using approved local datasets.

It must not silently modify production source code, proof authority, scope policy, scanner execution privileges or model deployment.

Code changes must be tested in an isolated development branch or disposable workspace.

Promotion requires explicit operator approval and applicable security regression tests.

Preserve the existing proposal approval and audit mechanisms.

## 7.3 Promotion and Rollback

Compare candidate improvements against the current baseline.

A candidate should be rejected if it:

- Produces new unsupported confirmations.
- Increases critical false-negative behavior.
- Introduces evidence fabrication.
- Weakens scope or offline enforcement.
- Exposes sensitive data.
- Breaks compatibility.
- Exceeds resource budgets without sufficient benefit.

Prefer Pareto improvements across accuracy, recall, runtime and resource usage.

Do not optimize precision by suppressing all findings.

Do not optimize recall by classifying everything as vulnerable.

Keep versioned improvement history.

Allow reverting to the last validated configuration.

---

# PART 8 — OPTIONAL MODEL FINE-TUNING

## 8.1 Fine-Tuning Is Not the First Learning Layer

First implement and benchmark:

1. Deterministic baseline.
2. Existing LLM without scenario retrieval.
3. LLM with reviewed scenario retrieval.
4. LLM with memory and feedback-aware retrieval.
5. Optional tuned model.

Only pursue fine-tuning if simpler approaches are insufficient and suitable approved data exists.

## 8.2 Dataset Builder

Implement an optional dataset-preparation workflow capable of producing reviewed training examples.

Use explicit training permission and provenance.

Support tasks such as:

- Vulnerability classification.
- Evidence-grounded explanation.
- False-positive analysis.
- Root-cause identification.
- Missing-evidence recognition.
- Secure remediation explanation.
- Safe validation planning.

Do not create training examples from unverified scanner findings as if they were confirmed ground truth.

Do not automatically ingest private bug bounty submissions.

Exclude or quarantine sensitive, poisoned, contradictory, low-confidence or license-incompatible records.

Support revocation and regeneration of affected datasets and derived retrieval indexes.

## 8.3 Training Strategy

If permitted and beneficial, support optional parameter-efficient training, such as LoRA/QLoRA, through a separately installed approved training environment.

Do not assume training a 4B model is practical within the Kali VM's existing memory allocation.

Prefer separate training execution on hardware with sufficient available RAM/VRAM.

The default TBHM release must not require a training framework or bundled model weights.

Record:

- Base model identifier.
- License.
- Dataset version.
- Training configuration.
- Adapter version.
- Hardware.
- Resource usage.
- Validation metrics.
- Held-out metrics.
- Known failure modes.

## 8.4 Model Promotion Gate

Never automatically deploy a newly trained model because training completed successfully.

Compare against the unchanged baseline and the RAG-assisted baseline.

Require meaningful improvements without unacceptable security regressions.

Support candidate, approved and rollback model versions.

If fine-tuning cannot be validated, keep the existing working inference model.

---

# PART 9 — KALI VM AND HARDWARE OPTIMIZATION

## 9.1 Target Environment

Optimize for the following workstation class:

Host:
- Windows.
- 16 GB RAM.
- NVIDIA RTX-class GPU with 8 GB VRAM.
- VMware Workstation.

Guest:
- Kali Linux x86-64.
- Approximately 6 GB RAM initially.
- Approximately 3–4 GB swap.
- Shared host resources with other laboratory VMs.

Do not assume direct CUDA access to the host GPU from a standard VMware Kali guest.

## 9.2 Resource-Aware Execution

Add or improve runtime resource monitoring for:

- Available RAM.
- CPU load.
- Disk space.
- Process count.
- Scanner concurrency.
- Model readiness.
- Optional GPU availability.

Use conservative default budgets.

Implement bounded queues, backpressure and cancellation.

Allow the operator to control worker concurrency and model context limits.

Separate interactive scanning from expensive learning and evaluation tasks.

Never crash an active scan merely because the optional LLM is unavailable.

Do not silently discard failed learning jobs; record their failure and permit deliberate retry.

## 9.3 Python Runtime Compatibility

The existing package requires Python 3.12.

Verify support on the target Kali installation.

Preserve compatibility with the existing hash-locked dependencies.

Support a separate Python 3.12 runtime without modifying Kali's system Python.

Do not install incompatible dependencies into the global environment.

Validate clean offline installation.

## 9.4 Local Model Architecture

Support practical configurations:

- Scanner-only mode.
- Retrieval-only mode.
- Local LLM in the guest when resources allow.
- Optional approved host-side model service through a narrowly scoped authenticated companion interface.

Do not assume the Windows host's loopback interface is the Kali guest's loopback interface.

Do not expose an unauthenticated Ollama endpoint to the LAN.

Do not disable TLS or trust protections for convenience.

Preserve strict offline behavior and document that offline mode may prevent communication with model services.

Use small quantized models as an evaluation starting point, not as a performance guarantee.

Record actual performance measurements before choosing defaults.

---

# PART 10 — LEARNING FROM REAL SECURITY RESEARCH

Implement a reviewed outcome-feedback workflow.

The operator should be able to mark a result as:

- Confirmed by technical proof.
- Refuted by technical proof.
- Inconclusive.
- False positive.
- Duplicate.
- Accepted by a program.
- Informative.
- Not applicable.
- Out of scope.
- Pending.
- Unsubmitted.

Require supporting context and evidence references where applicable.

Do not infer technical validity solely from program disposition.

For example:

A duplicate finding may still be technically valid.

A rejected submission may reflect scope, policy or report quality rather than absence of a vulnerability.

A technically confirmed issue is not automatically eligible for a bounty reward.

Use reviewed outcome data to improve:

- Finding prioritization.
- Duplicate recognition.
- Evidence collection.
- Report quality.
- Vulnerability-specific investigation.
- Understanding recurring false positives.

Do not treat bounty reward prediction as a verified scientific metric without appropriate data.

---

# PART 11 — SCENARIO-BASED RESEARCH ASSISTANT

The LLM should help the operator answer questions such as:

- Have we seen a similar vulnerability pattern before?
- Which reviewed scenario is most relevant?
- What failed last time?
- Was the previous finding confirmed or inconclusive?
- Which safe verification approach produced reliable evidence?
- What controls were missing?
- What changed between the previous and current test?
- Is this likely to be a duplicate observation?
- What source-code path should receive further review?
- What evidence is required for a stronger report?
- Why did a prior model recommendation fail?
- Which scanner settings previously exhausted budgets?
- Which vulnerability class has the weakest measured coverage?

Responses must cite stored scenario IDs and evidence IDs.

The model must acknowledge missing information.

Do not invent past tests or outcomes.

Do not execute network attacks merely because a retrieved scenario suggests a technique.

---

# PART 12 — OPERATOR INTERFACE AND LEARNING DASHBOARD

Integrate learning visibility into the existing OPERATOR interface without breaking the current reports.

Prefer an additive local dashboard or existing interface extension.

Include:

### Learning Overview

- Number of reviewed scenarios.
- Verified scenarios.
- Refuted scenarios.
- Inconclusive scenarios.
- Known mistake patterns.
- Recent learning updates.
- Model version.
- Last completed evaluation.

### Model Performance

- Precision and recall by supported task.
- False-positive and false-negative trends.
- Citation accuracy.
- Abstention.
- Evaluation sample sizes.
- Resource usage.
- Comparison with earlier model versions.

### Scenario Library

- Searchable reviewed scenarios.
- Vulnerability classification.
- Technology.
- Root cause.
- Outcome.
- Related scenarios.
- Permission/review status.

### Improvement Center

- Candidate improvements.
- Supporting evidence.
- Test results.
- Expected benefit.
- Regression risks.
- Approval status.
- Rollback history.

### Daily / Run Summary

After a run, provide:

- What was tested.
- What was discovered.
- What was confirmed.
- What remained inconclusive.
- What the model learned through reviewed feedback.
- Which prior mistakes recurred.
- Which recommendations were useful.
- What should be investigated next.
- What improvements require operator approval.

Do not present unreviewed model observations as learned facts.

---

# PART 13 — ADVERSARIAL SECURITY OF THE LEARNING ENGINE

Treat all imported cases, logs, scanner output, source code and model responses as potentially untrusted.

Test against:

- Prompt injection.
- Retrieval poisoning.
- Forged scenario labels.
- Fabricated evidence references.
- Cross-project information leakage.
- Sensitive-data memorization.
- Unauthorized dataset inclusion.
- Training/evaluation leakage.
- Corrupt or oversized records.
- Symlink/path traversal in imported files.
- Resource exhaustion.
- Model-generated shell commands.
- Fake proof receipts.
- Attempts to change security policies through retrieved instructions.

The model must not acquire privileged execution capabilities through the learning pipeline.

Proof confirmation stays under deterministic, authenticated verification contracts.

Only reviewed labels may enter the trusted supervised-learning dataset.

Maintain auditable provenance for every promoted learning artifact.

---

# PART 14 — REQUIRED TEST SUITES

Build tests for:

## Legacy Compatibility

All previous phases, arguments, reports, evidence contracts and database semantics.

## Learning Ingestion

Valid records, duplicates, corrupt records, sensitive files, revoked records and unsupported formats.

## Scenario Retrieval

Relevant matches, unrelated matches, stale cases, poisoned records and cross-project isolation.

## Model Evaluation

Correct labels, conflicting labels, hallucinated citations, abstentions, metric denominators and leakage detection.

## Improvement Proposals

Candidate creation, evidence linkage, rejection, approval, promotion and rollback.

## Fine-Tuning Preparation

Dataset permissions, deduplication, split isolation, revocation and reproducibility.

Do not require a real model to test deterministic dataset and evaluation logic.

## Runtime Performance

Small-memory operation, bounded concurrent workers, model unavailability, cancellation, disk-pressure handling and resource cleanup.

## Security Regression

Scope boundaries, offline isolation, request limits, proof integrity and artifact privacy.

## Release Validation

Clean extraction, offline installation, compile/import, integration tests, manifest validation and installed CLI smoke tests.

Do not fabricate model benchmarks when a model is unavailable.

---

# PART 15 — REQUIRED IMPLEMENTATION ORDER

Execute work in the following sequence.

### Stage 1 — Baseline Audit

Inspect the current source and run tests.

Produce a verified gap matrix.

### Stage 2 — Critical Fixes

Resolve reproducible containment, trust, privacy and compatibility defects.

### Stage 3 — Scenario Learning

Extend the existing AI-plane with reviewed structured scenario memory and bounded retrieval.

### Stage 4 — Self-Evaluation

Implement independent model evaluation, historical comparisons and error categorization.

### Stage 5 — Controlled Improvement

Implement evidence-backed improvement proposals, isolated testing and promotion gates.

### Stage 6 — Proof Expansion

Implement the highest-value additional strict verifier or verifier generalization supported by complete test evidence.

### Stage 7 — Hardware Optimization

Validate normal execution on a resource-constrained Kali VM.

### Stage 8 — Optional Fine-Tuning Preparation

Prepare a lawful dataset and training interface only if justified.

Actual model training is optional and must not block the core release.

### Stage 9 — Final Regression and Packaging

Execute the full test suite and release validation.

Do not spend the entire implementation budget on exploratory research, architecture diagrams or an unfinished training pipeline.

A working, measurable, incremental release is better than a large unverified redesign.

---

# PART 16 — RELEASE DELIVERABLES

Deliver:

1. A complete updated TBHM source distribution.
2. A validated Linux x86-64 release ZIP, if the environment supports packaging.
3. Updated installation instructions for Kali.
4. Release notes and changelog.
5. Source patch.
6. Full regression results.
7. Proof-contract coverage matrix.
8. Transport containment matrix.
9. Scenario-learning architecture and schema documentation.
10. Dataset permission and provenance specification.
11. Learning pipeline tests.
12. Self-evaluation benchmark reports.
13. Baseline versus candidate model comparisons, when real models are available.
14. Improvement proposal and rollback documentation.
15. Hardware and memory measurements, when executable.
16. Updated feature-gap roadmap.
17. SHA-256 and release manifest.
18. Clearly documented unresolved limitations.

Preserve the original working release separately.

Do not publish the ZIP as fully validated if release-blocking tests fail.

Do not create fake passing benchmarks or placeholder implementations.

---

# PART 17 — SUCCESS CRITERIA

TBHM v4.2.5 should demonstrate meaningful improvements in the following areas.

## Security Tool Quality

- Existing valid behavior preserved.
- Known defects corrected.
- No weakening of proof authority.
- Better tested runtime boundaries.
- More reliable evidence handling.
- Stronger vulnerability-specific validation where completed.

## Learning Quality

- Reviewed scenarios persist across runs.
- Similar cases can be retrieved with provenance.
- The model can reference relevant previous mistakes.
- Contradictory or unverified cases are not promoted to ground truth.
- Evaluation uses independent outcomes.
- Candidate improvements can be compared to a baseline.
- Changes can be rejected and rolled back.

## Practical Usability

- Compatible with the target Kali VM configuration.
- Sensible resource budgets.
- Optional model operation.
- No mandatory external paid service.
- No forced cloud model dependency.
- No unauthorized network operations.
- No uncontrolled self-modification.

## Measurable Improvement

At least one learning or model-assistance capability must demonstrate an actual comparative evaluation against a defined baseline.

If no real model runtime or eligible scenario corpus exists, demonstrate the complete deterministic learning/evaluation workflow using documented synthetic fixtures and mark real-model effectiveness UNVERIFIED.

Do not confuse functional tests with demonstrated accuracy improvements.

---

# FINAL INSTRUCTION — IMPLEMENT, TEST, LEARN AND IMPROVE

Use the actual TBHM v4.2.4 source as the baseline.

Preserve the existing system.

Fix real defects.

Improve the strict verification architecture.

Extend the existing AI-plane rather than replacing it.

Build a persistent reviewed scenario-memory and feedback system.

Make the LLM capable of analyzing its historical mistakes, evaluating its recommendations and producing controlled, measurable improvement proposals.

Use RAG and validated memory as the default learning mechanism.

Support optional fine-tuning only when data permission, resources and independent evaluation justify it.

Do not allow the model to silently modify production code, proof receipts, authorization boundaries or deployed weights.

Do not stop after planning.

Implement, test, document and package the highest-value verified improvements that can actually be completed.

**The goal is not a model that merely says it is learning.**

**The goal is a security research platform that can demonstrate what it learned, how that changed its recommendations, whether those recommendations improved, and why the operator should trust the evidence.**