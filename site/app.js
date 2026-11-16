(() => {
  "use strict";

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

  const money = (value) => `$${value.toFixed(2)}`;

  const limits = {
    daily: 50,
    spent: 31.2,
    maxPerTx: 25,
    hardCeiling: 25,
    autoExec: 1,
    humanUpper: 10,
  };

  const state = {
    amount: 0.42,
    merchant: "allow",
    epoch: "active",
  };

  const consoleEl = $("#policy-console");
  if (consoleEl) {
    const amountInput = $("#amount");
    const amountOut = $("#amount-out");
    const merchantSelect = $("#merchant");
    const policyWord = $("#policy-word");
    const policyDetail = $("#policy-detail");
    const decision = $("[data-decision]");
    const vaultStatus = $("#vault-status");
    const amountButtons = $$("[data-amount]");
    const epochButtons = $$("[data-epoch]");
    const checks = {
      allowlist: $('[data-check="allowlist"]'),
      counterparty: $('[data-check="counterparty"]'),
      maxtx: $('[data-check="maxtx"]'),
      daily: $('[data-check="daily"]'),
      epoch: $('[data-check="epoch"]'),
    };

    const remaining = () => limits.daily - limits.spent;

    const evaluatePolicy = () => {
      if (state.merchant === "unknown") {
        return {
          state: "deny",
          word: "DENY",
          detail: "Merchant is not on the destination allowlist.",
        };
      }
      if (state.amount > limits.hardCeiling) {
        return {
          state: "deny",
          word: "DENY",
          detail: "Tier-3 hard policy ceiling exceeded.",
        };
      }
      if (state.amount > remaining()) {
        return {
          state: "deny",
          word: "DENY",
          detail: `Only ${money(remaining())} remains in the rolling 24h allowance.`,
        };
      }
      if (state.amount <= limits.autoExec) {
        return {
          state: "allow",
          word: "ALLOW",
          detail: "Within the Tier 1 auto-exec band.",
        };
      }
      return {
        state: "review",
        word: "REVIEW",
        detail:
          state.amount <= limits.humanUpper
            ? "Tier 2: spend sits in the human review band."
            : "Tier 3: below the hard ceiling, above the human review band.",
      };
    };

    const evaluateVault = () => {
      if (state.epoch === "stale") return "claimVoucher() → REVERT SessionEpochMismatch()";
      if (state.merchant === "unknown") return "claimVoucher() → REVERT UnauthorizedMerchant()";
      if (state.amount > limits.maxPerTx) return "claimVoucher() → REVERT MaxPerTxExceeded()";
      if (limits.spent + state.amount > limits.daily) return "claimVoucher() → REVERT DailyLimitExceeded()";
      return "claimVoucher() → OK · delta settles";
    };

    const setCheck = (node, passed, label) => {
      if (!node) return;
      node.dataset.status = passed ? "pass" : "fail";
      const status = node.querySelector("b");
      if (status) status.textContent = passed ? "pass" : "fail";
      if (label) node.querySelector("span").textContent = label;
    };

    const render = () => {
      amountOut.textContent = money(state.amount);
      amountInput.value = String(state.amount);

      amountButtons.forEach((button) => {
        const active = Number(button.dataset.amount) === state.amount;
        button.classList.toggle("is-active", active);
        button.setAttribute("aria-pressed", String(active));
      });
      epochButtons.forEach((button) => {
        const active = button.dataset.epoch === state.epoch;
        button.classList.toggle("is-active", active);
        button.setAttribute("aria-pressed", String(active));
      });

      const policy = evaluatePolicy();
      decision.dataset.state = policy.state;
      policyWord.textContent = policy.word;
      policyDetail.textContent = policy.detail;
      vaultStatus.textContent = evaluateVault();

      setCheck(checks.allowlist, state.merchant === "allow", "Destination allowlist");
      setCheck(checks.counterparty, true, "Counterparty floor");
      setCheck(checks.maxtx, state.amount <= limits.maxPerTx, "delta ≤ maxPerTx");
      setCheck(checks.daily, limits.spent + state.amount <= limits.daily, "rolling 24h ceiling");
      setCheck(checks.epoch, state.epoch === "active", "active delegation epoch");
    };

    amountInput.addEventListener("input", () => {
      state.amount = Math.round(Number(amountInput.value) * 100) / 100;
      render();
    });

    amountButtons.forEach((button) => {
      button.addEventListener("click", () => {
        state.amount = Number(button.dataset.amount);
        render();
      });
    });

    merchantSelect.addEventListener("change", () => {
      state.merchant = merchantSelect.value;
      render();
    });

    epochButtons.forEach((button) => {
      button.addEventListener("click", () => {
        state.epoch = button.dataset.epoch;
        render();
      });
    });

    render();
  }

  // Mobile nav.
  const menuToggle = $("[data-menu-toggle]");
  const nav = $("#site-nav");
  const closeMenu = () => {
    if (!menuToggle || !nav) return;
    menuToggle.setAttribute("aria-expanded", "false");
    nav.removeAttribute("data-open");
  };

  if (menuToggle && nav) {
    menuToggle.addEventListener("click", () => {
      const open = menuToggle.getAttribute("aria-expanded") === "true";
      menuToggle.setAttribute("aria-expanded", String(!open));
      if (open) nav.removeAttribute("data-open");
      else nav.setAttribute("data-open", "true");
    });
    $$("a", nav).forEach((link) => link.addEventListener("click", closeMenu));
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") closeMenu();
    });
    window.addEventListener("resize", () => {
      if (window.innerWidth > 900) closeMenu();
    });
  }

  // Section nav state.
  const navLinks = $$("[data-nav]");
  const sections = navLinks
    .map((link) => {
      const id = link.getAttribute("href");
      const section = id && id.startsWith("#") ? $(id) : null;
      return section ? { link, section } : null;
    })
    .filter(Boolean);

  if (sections.length && "IntersectionObserver" in window) {
    const navObserver = new IntersectionObserver(
      (entries) => {
        const visible = entries
          .filter((entry) => entry.isIntersecting)
          .sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
        if (!visible) return;
        sections.forEach(({ link, section }) => {
          if (section === visible.target) link.setAttribute("aria-current", "true");
          else link.removeAttribute("aria-current");
        });
      },
      { rootMargin: "-24% 0px -58% 0px", threshold: [0, 0.15, 0.4] },
    );
    sections.forEach(({ section }) => navObserver.observe(section));
  }

  // Copyable addresses.
  const copyText = async (text) => {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return;
    }
    const area = document.createElement("textarea");
    area.value = text;
    area.setAttribute("readonly", "");
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.appendChild(area);
    area.select();
    document.execCommand("copy");
    area.remove();
  };

  $$("[data-copy]").forEach((button) => {
    const label = button.querySelector("span");
    button.addEventListener("click", async () => {
      const original = label ? label.textContent : "";
      try {
        await copyText(button.dataset.copy || "");
        if (label) label.textContent = "copied";
      } catch {
        if (label) label.textContent = "copy failed";
      }
      window.setTimeout(() => {
        if (label) label.textContent = original || "copy";
      }, 1600);
    });
  });

  const year = $("[data-year]");
  if (year) year.textContent = String(new Date().getFullYear());
})();
