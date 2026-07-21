const useCases = [
  {
    number: "01",
    title: "Customer & field copilots",
    text: "Keep estimates, decisions, and customer context close without dragging every old conversation into every prompt.",
    tone: "mint",
  },
  {
    number: "02",
    title: "Long-running research",
    text: "Preserve competing hypotheses, surface contradictions, and let useful context rest until the inquiry returns.",
    tone: "amber",
  },
  {
    number: "03",
    title: "Regulated workflows",
    text: "Add explicit confidence gates, encrypted vector paths, and a fail-closed production boundary around sensitive retrieval.",
    tone: "blue",
  },
  {
    number: "04",
    title: "Personal knowledge agents",
    text: "Build continuity that follows current intent instead of turning a lifetime of notes into permanent prompt baggage.",
    tone: "violet",
  },
  {
    number: "05",
    title: "Multi-agent operations",
    text: "Give specialist agents a shared memory policy while the host application keeps authorization and payload ownership.",
    tone: "coral",
  },
  {
    number: "06",
    title: "Case & project memory",
    text: "Carry forward the decisions that matter, checkpoint active work, and archive context with its lifecycle metadata intact.",
    tone: "lime",
  },
];

const reasons = [
  {
    title: "Less context drag",
    text: "Intent proximity and decay keep the active workspace focused, reducing the temptation to send an ever-growing transcript to the model.",
    metric: "L1",
    label: "active focus",
  },
  {
    title: "Better memory hygiene",
    text: "Twilight, reinforcement, locks, and resurrection give memory an understandable lifecycle instead of a binary keep-or-delete switch.",
    metric: "3",
    label: "memory tiers",
  },
  {
    title: "Honest uncertainty",
    text: "Confidence bands make weak reconstruction visible. Inferential answers require consent; data obscurity stops generation.",
    metric: "5",
    label: "confidence bands",
  },
  {
    title: "A real privacy boundary",
    text: "Use plaintext locally, AES-GCM in staging, local CKKS, or an attested enclave path—with capabilities reported instead of implied.",
    metric: "4",
    label: "security modes",
  },
];

const stackSteps = [
  { label: "Your product", sub: "UI, API, agent" },
  { label: "Agent runtime", sub: "Tools + model" },
  { label: "Echo Veil", sub: "Memory policy layer", active: true },
  { label: "Your data plane", sub: "Embeddings + payloads" },
];

export default function Home() {
  return (
    <>
      <a className="skip-link" href="#main-content">
        Skip to main content
      </a>
      <main id="main-content" tabIndex={-1}>
        <div className="grain" aria-hidden="true" />

      <nav className="nav shell" aria-label="Primary navigation">
        <a className="brand" href="#top" aria-label="Echo Veil home">
          <span className="brand-mark" aria-hidden="true">
            <i />
            <i />
            <i />
          </span>
          <span>Echo Veil</span>
        </a>
        <div className="nav-links">
          <a href="#system">System</a>
          <a href="#use-cases">Use cases</a>
          <a href="#stack">Stack fit</a>
          <a href="https://github.com/Seabass-up/echo-veil">GitHub ↗</a>
          <a className="nav-cta" href="#start">
            Explore Echo Veil <span aria-hidden="true">↗</span>
          </a>
        </div>
      </nav>

      <section className="hero shell" id="top">
        <div className="hero-copy">
          <div className="eyebrow">
            <span className="status-dot" /> v0.5.0 · Protected semantic memory
          </div>
          <h1>
            Memory that knows
            <br />
            <em>what to keep.</em>
          </h1>
          <p className="hero-lede">
            Echo Veil gives AI agents encrypted semantic recall with an
            answerability check, visible ranking ambiguity, and a conservative
            read-only layer that stays available when the embedding service does
            not—without turning guesses into facts.
          </p>
          <div className="hero-actions">
            <a className="button button-primary" href="#system">
              See the system <span aria-hidden="true">↓</span>
            </a>
            <a className="text-link" href="#stack">
              Where it fits in your stack <span aria-hidden="true">→</span>
            </a>
          </div>
          <div className="hero-proof" aria-label="Product attributes">
            <span>Release v0.5.0</span>
            <span>Open source</span>
            <span>Commercial use free</span>
            <span>Fail-closed production mode</span>
          </div>
        </div>

        <div className="hero-visual" aria-label="Echo Veil memory garden visualization">
          <div className="orbit orbit-one" />
          <div className="orbit orbit-two" />
          <div className="orbit orbit-three" />
          <div className="memory-node node-active">
            <span>Active</span>
            <strong>Memory Vine</strong>
            <small>intent nearby</small>
          </div>
          <div className="memory-node node-resting">
            <span>Resting</span>
            <strong>Twilight</strong>
            <small>ready to return</small>
          </div>
          <div className="memory-node node-conflict">
            <span>Tension</span>
            <strong>Two truths</strong>
            <small>both preserved</small>
          </div>
          <div className="seed-crystal">
            <span className="seed-glow" />
            <span className="seed-label">Current intent</span>
            <strong>Seed<br />Crystal</strong>
            <small>the north star</small>
          </div>
          <div className="visual-caption">
            <span>LIVE SIGNAL</span>
            <div className="signal-line"><i /><i /><i /><i /><i /></div>
          </div>
        </div>
      </section>

      <section className="marquee" aria-label="Echo Veil capabilities">
        <span className="sr-only">
          Intent proximity, organic decay, conflict preservation, confidence
          gating, and encrypted retrieval.
        </span>
        <div className="marquee-track" aria-hidden="true">
          <span>INTENT PROXIMITY</span><i>✦</i>
          <span>ORGANIC DECAY</span><i>✦</i>
          <span>CONFLICT PRESERVATION</span><i>✦</i>
          <span>CONFIDENCE GATING</span><i>✦</i>
          <span>ENCRYPTED RETRIEVAL</span><i>✦</i>
          <span>INTENT PROXIMITY</span><i>✦</i>
          <span>ORGANIC DECAY</span><i>✦</i>
        </div>
      </section>

      <section className="system-section shell" id="system">
        <header className="section-head">
          <div>
            <span className="section-index">01 / THE SYSTEM</span>
            <h2>A memory garden,<br />not a memory dump.</h2>
          </div>
          <p>
            Most agent memory gets bigger forever. Echo Veil uses current
            intent to decide what stays active, what rests, and what moves into
            durable retrieval—without erasing the history of how knowledge
            changed.
          </p>
        </header>

        <div className="layer-visual">
          <div className="layer layer-one">
            <div className="layer-title">
              <span>LEVEL 1</span>
              <strong>Active Workspace</strong>
              <small>Fast · Focused · RAM</small>
            </div>
            <div className="vine-field" aria-hidden="true">
              <i className="vine v1" /><i className="vine v2" />
              <i className="vine v3" /><i className="vine v4" />
              <span className="crystal-mini" />
            </div>
            <p>Memory Vines orbit current intent. Low-proximity context moves into Twilight instead of cluttering every turn.</p>
          </div>
          <div className="layer layer-two">
            <div className="layer-title">
              <span>LEVEL 2</span>
              <strong>Metadata Index</strong>
              <small>Searchable · Sparse · Durable</small>
            </div>
            <div className="index-map" aria-hidden="true">
              {Array.from({ length: 18 }).map((_, index) => <i key={index} />)}
            </div>
            <p>Compact vector metadata and lifecycle clues make cold memories findable without loading the whole archive.</p>
          </div>
          <div className="layer layer-three">
            <div className="layer-title">
              <span>LEVEL 3</span>
              <strong>Latent Archive</strong>
              <small>Cold · Historical · Recoverable</small>
            </div>
            <div className="archive-rings" aria-hidden="true">
              <i /><i /><i /><span>history<br />rests here</span>
            </div>
            <p>Evicted context becomes recoverable history. Fossilized Echoes preserve contradiction instead of rewriting the past.</p>
          </div>
          <div className="shield-rail">
            <span className="shield-lock">✦</span>
            <strong>Cryptographic Shield</strong>
            <span>Development → AES-GCM → Local CKKS → Attested enclave</span>
          </div>
        </div>
      </section>

      <section className="use-section" id="use-cases">
        <div className="shell">
          <header className="section-head section-head-light">
            <div>
              <span className="section-index">02 / USE CASES</span>
              <h2>Built for agents<br />with a long story.</h2>
            </div>
            <p>
              If your AI needs continuity across days, projects, customers, or
              investigations—but cannot afford infinite context—Echo Veil gives
              it a disciplined way to remember.
            </p>
          </header>

          <div className="use-grid">
            {useCases.map((item) => (
              <article className={`use-card ${item.tone}`} key={item.number}>
                <span className="card-number">{item.number}</span>
                <div className="card-orb" aria-hidden="true"><i /><i /></div>
                <h3>{item.title}</h3>
                <p>{item.text}</p>
                <span className="card-arrow" aria-hidden="true">↗</span>
              </article>
            ))}
          </div>
        </div>
      </section>

      <section className="why-section shell">
        <header className="section-head">
          <div>
            <span className="section-index">03 / WHY ECHO VEIL</span>
            <h2>Smaller context.<br />Stronger continuity.</h2>
          </div>
          <p>
            Add Echo Veil when a vector database alone is not enough. It adds
            policy, metabolism, confidence, and privacy around retrieval—while
            leaving your models and payload store in your control.
          </p>
        </header>
        <div className="reason-grid">
          {reasons.map((reason) => (
            <article className="reason" key={reason.title}>
              <div className="reason-metric"><strong>{reason.metric}</strong><span>{reason.label}</span></div>
              <div><h3>{reason.title}</h3><p>{reason.text}</p></div>
            </article>
          ))}
        </div>
      </section>

      <section className="stack-section" id="stack">
        <div className="shell stack-shell">
          <header className="stack-intro">
            <span className="section-index">04 / WHERE IT FITS</span>
            <h2>The policy layer between<br />your agent and its memory.</h2>
            <p>
              Echo Veil does not replace your model, embedding provider, or
              authorized content store. It coordinates what memory is active,
              what is retrievable, and when confidence is too low to generate.
            </p>
          </header>

          <div className="stack-map" aria-label="Echo Veil position in an AI application stack">
            {stackSteps.map((step, index) => (
              <div className="stack-row-wrap" key={step.label}>
                <div className={`stack-row ${step.active ? "stack-active" : ""}`}>
                  <span className="stack-count">0{index + 1}</span>
                  <div><strong>{step.label}</strong><small>{step.sub}</small></div>
                  {step.active && <span className="stack-badge">ADD HERE</span>}
                </div>
                {index < stackSteps.length - 1 && <span className="stack-connector" aria-hidden="true">↓</span>}
              </div>
            ))}
          </div>

          <div className="integration-notes">
            <div><span>QUALITY</span><strong>42 / 42 retrieval gate</strong><p>Local Qwen3 passed the committed keyword, paraphrase, update, temporal, and long-memory suite.*</p></div>
            <div><span>OUTPUT</span><strong>Answerable, not just similar</strong><p>Predicate matching rejects same-person records that do not answer the requested fact.</p></div>
            <div><span>BOUNDARY</span><strong>Fail-closed production</strong><p>Production requires the configured attested enclave shield.</p></div>
            <div className="host-support">
              <strong>Adapters for the agents you already use.</strong>
              <div aria-label="Supported agent runtime adapters">
                <span>OPENCLAW</span><span>HERMES</span><span>CODEX</span>
                <span>CLAUDE CODE</span><span>PI</span><span>OPENCODE</span>
                <span>DROID</span><span>GOOSE</span><span>MERCURY*</span>
              </div>
              <p>* Mercury readiness skill today; full structured tools await a documented host boundary.</p>
              <p>* Neutral synthetic regression suite, not a universal product comparison.</p>
            </div>
          </div>
        </div>
      </section>

      <section className="security-section shell">
        <div className="security-card">
          <div className="security-copy">
            <span className="section-index">05 / PRIVACY BY MODE</span>
            <h2>Start simple.<br />Harden without pretending.</h2>
            <p>
              Every environment says exactly what it can protect. Echo Veil
              refuses production startup when CKKS, verified hardware isolation,
              fresh attestation, or the proof gate is missing.
            </p>
            <div className="security-pills">
              <span>Capability report</span><span>Replay defense</span><span>Bounded inputs</span><span>Encrypted vectors</span>
            </div>
          </div>
          <div className="mode-list">
            <div><span>01</span><strong>Development</strong><small>Plaintext, local testing</small></div>
            <div><span>02</span><strong>Staging</strong><small>AES-GCM protected storage</small></div>
            <div><span>03</span><strong>Local private</strong><small>Native OpenFHE CKKS</small></div>
            <div className="mode-active"><span>04</span><strong>Production</strong><small>Attested enclave + ZKP gate</small></div>
          </div>
        </div>
      </section>

      <section className="cta-section shell" id="start">
        <div className="cta-orbit" aria-hidden="true"><i /><i /><i /></div>
        <span className="section-index">MEMORY, WITH BETTER JUDGMENT</span>
        <h2>Give your agent<br /><em>a wiser memory.</em></h2>
        <p>Echo Veil v0.5.0 · Open source under MIT · Free for personal and commercial use.</p>
        <div className="cta-actions">
          <a className="button button-primary" href="https://github.com/Seabass-up/echo-veil">View source on GitHub <span aria-hidden="true">↗</span></a>
          <a className="text-link" href="https://github.com/Seabass-up/echo-veil/blob/master/docs/AGENT_INTEGRATION.md">Read the integration guide <span aria-hidden="true">→</span></a>
        </div>
      </section>

      <footer className="footer shell">
        <a className="brand" href="#top">
          <span className="brand-mark" aria-hidden="true"><i /><i /><i /></span>
          <span>Echo Veil</span>
        </a>
        <p>A privacy-first memory system for AI agents, by <a href="https://algo-cli.com">Algo-cli.com</a>.</p>
        <div><a href="https://github.com/Seabass-up/echo-veil">GITHUB</a><a href="https://github.com/Seabass-up/echo-veil/security/policy">SECURITY</a><span>MIT LICENSE</span><span>© 2026 ALGO-CLI.COM</span></div>
      </footer>
      </main>
    </>
  );
}
