/* Independent KCHAT AI launcher fallback.
   Kept separate from the main app script so an unrelated app-script error
   cannot silently disable the AI launch button. */
(function () {
  "use strict";

  function openKchatAIFromLauncher() {
    const screen = document.getElementById("kchatAiScreen");
    const fab = document.getElementById("kchatAiFab");
    const app = document.getElementById("appScreen");
    if (!screen) {
      console.error("KCHAT AI screen element is missing.");
      return;
    }

    if (screen.parentElement !== document.body) {
      document.body.appendChild(screen);
    }

    screen.classList.remove("hidden");
    screen.style.setProperty("display", "flex", "important");
    screen.style.setProperty("visibility", "visible", "important");
    screen.style.setProperty("pointer-events", "auto", "important");
    screen.style.setProperty("position", "fixed", "important");
    screen.style.setProperty("inset", "0", "important");
    screen.style.setProperty("z-index", "2147483000", "important");

    if (app) {
      app.classList.remove("status-open");
      app.classList.add("mobile-ai-open");
    }
    if (fab) fab.classList.add("hidden");

    try {
      if (typeof window.openKchatAI === "function") {
        window.openKchatAI();
      } else {
        const input = document.getElementById("kchatAiInput");
        if (input) input.focus();
      }
    } catch (error) {
      console.error("KCHAT AI launcher error:", error);
    }
  }

  function closeKchatAIFromLauncher() {
    const screen = document.getElementById("kchatAiScreen");
    const fab = document.getElementById("kchatAiFab");
    const app = document.getElementById("appScreen");
    if (screen) screen.classList.add("hidden");
    if (app) app.classList.remove("mobile-ai-open");
    if (fab) fab.classList.remove("hidden");
  }

  document.addEventListener("pointerup", function (event) {
    const target = event.target instanceof Element ? event.target : null;
    const launcher = target && target.closest("#kchatAiFab");
    if (!launcher) return;
    event.preventDefault();
    event.stopPropagation();
    openKchatAIFromLauncher();
  }, true);

  document.addEventListener("click", function (event) {
    const target = event.target instanceof Element ? event.target : null;
    const launcher = target && target.closest("#kchatAiFab");
    if (!launcher) return;
    event.preventDefault();
    event.stopPropagation();
    openKchatAIFromLauncher();
  }, true);

  document.addEventListener("click", function (event) {
    const target = event.target instanceof Element ? event.target : null;
    if (target && target.closest("#kchatAiBack")) {
      event.preventDefault();
      closeKchatAIFromLauncher();
    }
  }, true);
})();