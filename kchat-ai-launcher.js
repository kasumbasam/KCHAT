/* Independent KCHAT AI launcher and mobile controls.
   This script keeps the AI controls working even if the main app script
   has an unrelated initialization error. */
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
    if (screen.parentElement !== document.body) document.body.appendChild(screen);
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
      if (typeof window.openKchatAI === "function") window.openKchatAI();
      else {
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
    const searchFab = document.getElementById("kchatAiSearchShortcut");
    const chatFab = document.getElementById("kchatAiChatFab");
    const app = document.getElementById("appScreen");
    const menu = document.getElementById("kchatAiMoreMenu");
    const more = document.getElementById("kchatAiMoreButton");
    if (screen) screen.classList.add("hidden");
    if (menu) menu.classList.add("hidden");
    if (more) more.setAttribute("aria-expanded", "false");
    if (app) app.classList.remove("mobile-ai-open");
    if (fab) fab.classList.remove("hidden");
    if (searchFab) searchFab.classList.remove("hidden");
    const chatScreen = document.getElementById("chatScreen");
    if (chatFab && chatScreen && !chatScreen.classList.contains("hidden")) chatFab.classList.remove("hidden");
  }

  function toggleKchatAIMenu(event) {
    const button = document.getElementById("kchatAiMoreButton");
    const menu = document.getElementById("kchatAiMoreMenu");
    if (!button || !menu) return;
    event.preventDefault();
    event.stopPropagation();
    if (typeof event.stopImmediatePropagation === "function") event.stopImmediatePropagation();
    const opening = menu.classList.contains("hidden");
    menu.classList.toggle("hidden", !opening);
    button.setAttribute("aria-expanded", String(opening));
    if (opening) {
      menu.style.setProperty("display", "flex", "important");
      menu.style.setProperty("z-index", "2147483001", "important");
    } else {
      menu.style.removeProperty("display");
    }
  }

  // Cancel native AI form navigation while allowing its app submit handler to run.
  document.addEventListener("submit", function (event) {
    const form = event.target;
    if (form && form.id === "kchatAiForm") event.preventDefault();
  }, true);

  document.addEventListener("pointerup", function (event) {
    const target = event.target instanceof Element ? event.target : null;
    if (!target || !target.closest("#kchatAiFab")) return;
    event.preventDefault();
    event.stopPropagation();
    openKchatAIFromLauncher();
  }, true);

  document.addEventListener("click", function (event) {
    const target = event.target instanceof Element ? event.target : null;
    if (!target) return;
    if (target.closest("#kchatAiFab")) {
      event.preventDefault();
      event.stopPropagation();
      if (typeof event.stopImmediatePropagation === "function") event.stopImmediatePropagation();
      openKchatAIFromLauncher();
      return;
    }
    if (target.closest("#kchatAiMoreButton")) {
      toggleKchatAIMenu(event);
      return;
    }
    if (target.closest("#kchatAiBack")) {
      event.preventDefault();
      event.stopPropagation();
      if (typeof event.stopImmediatePropagation === "function") event.stopImmediatePropagation();
      closeKchatAIFromLauncher();
      return;
    }
    const menu = document.getElementById("kchatAiMoreMenu");
    const wrap = document.querySelector(".kchat-ai-menu-wrap");
    if (menu && wrap && !wrap.contains(target)) {
      menu.classList.add("hidden");
      menu.style.removeProperty("display");
      const button = document.getElementById("kchatAiMoreButton");
      if (button) button.setAttribute("aria-expanded", "false");
    }
  }, true);
})();