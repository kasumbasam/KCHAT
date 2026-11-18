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
    if (screen) {
      screen.classList.add("hidden");
      // Opening applies important inline styles for mobile visibility.
      // Remove them on close so the hidden class can actually hide the screen.
      ["display", "visibility", "pointer-events", "position", "inset", "z-index"].forEach(property => {
        screen.style.removeProperty(property);
      });
    }
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

  // Standalone AI sender: this remains available even if the main app script fails
  // during initialization. It owns the tap and submit events before other handlers.
  let aiSending = false;
  let aiConversationId = "";
  let aiHistory = [];

  function readAiToken() {
    try {
      const stored = localStorage.getItem("kchat_token");
      if (stored) return stored;
    } catch (_) {}
    const match = document.cookie.match(/(?:^|;\s*)kchat_token=([^;]*)/);
    if (!match) return "";
    try { return decodeURIComponent(match[1]); } catch (_) { return match[1]; }
  }

  function aiStatus(message, isError) {
    const note = document.querySelector("#kchatAiScreen .kchat-ai-connection-note");
    if (note) {
      note.textContent = message;
      note.style.color = isError ? "#ff647c" : "";
    }
  }

  function aiBubble(role, message) {
    const list = document.getElementById("kchatAiMessages");
    if (!list) return null;
    const bubble = document.createElement("div");
    bubble.className = role === "user" ? "kchat-ai-user-message" : "kchat-ai-assistant-message";
    bubble.textContent = message;
    bubble.style.whiteSpace = "pre-wrap";
    bubble.style.overflowWrap = "anywhere";
    list.appendChild(bubble);
    list.scrollTop = list.scrollHeight;
    return bubble;
  }

  async function sendAiFromLauncher(event) {
    if (event) {
      event.preventDefault();
      event.stopPropagation();
      if (typeof event.stopImmediatePropagation === "function") event.stopImmediatePropagation();
    }
    const input = document.getElementById("kchatAiInput");
    const button = document.getElementById("kchatAiSendButton");
    const value = input ? input.value.trim() : "";
    if (!value || aiSending) return;
    const token = readAiToken();
    if (!token) {
      aiStatus("Please log in to use KCHAT AI.", true);
      return;
    }

    const welcome = document.querySelector("#kchatAiScreen .kchat-ai-welcome");
    if (welcome) welcome.classList.add("hidden");
    aiBubble("user", value);
    input.value = "";
    aiHistory.push({ role: "user", content: value });
    aiSending = true;
    if (button) button.disabled = true;
    aiStatus("KCHAT AI is working…", false);
    const reply = aiBubble("assistant", "Thinking…");
    let received = "";

    try {
      const response = await fetch("/api/ai/chat", {
        method: "POST",
        headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" },
        body: JSON.stringify({ messages: aiHistory, conversation_id: aiConversationId || null })
      });
      if (!response.ok) {
        let data = {};
        try { data = await response.json(); } catch (_) {}
        throw new Error(data.error || data.detail || "KCHAT AI request failed (" + response.status + ").");
      }
      if (!response.body) throw new Error("This browser cannot receive the AI response. Please reload KCHAT.");
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      while (true) {
        const part = await reader.read();
        buffer += decoder.decode(part.value || new Uint8Array(), { stream: !part.done });
        const rows = buffer.split("\n");
        buffer = rows.pop() || "";
        for (const row of rows) {
          if (!row.trim()) continue;
          const item = JSON.parse(row);
          if (item.type === "delta") {
            received += item.content || "";
            if (reply) reply.textContent = received;
            const list = document.getElementById("kchatAiMessages");
            if (list) list.scrollTop = list.scrollHeight;
            aiStatus("KCHAT AI is replying…", false);
          } else if (item.type === "error") {
            throw new Error(item.error || "KCHAT AI could not complete the reply.");
          } else if (item.type === "done" && item.conversation_id) {
            aiConversationId = item.conversation_id;
          }
        }
        if (part.done) break;
      }
      if (buffer.trim()) {
        const item = JSON.parse(buffer);
        if (item.type === "error") throw new Error(item.error || "KCHAT AI could not complete the reply.");
        if (item.type === "done" && item.conversation_id) aiConversationId = item.conversation_id;
      }
      if (!received.trim()) throw new Error("KCHAT AI returned an empty answer. Please try again.");
      aiHistory.push({ role: "assistant", content: received });
      aiStatus("KCHAT AI is ready.", false);
    } catch (error) {
      if (reply) reply.textContent = error.message || "KCHAT AI could not respond.";
      aiStatus("Message not completed. Please try again.", true);
    } finally {
      aiSending = false;
      if (button) button.disabled = false;
      if (input) input.focus();
    }
  }

  document.addEventListener("click", function (event) {
    const target = event.target instanceof Element ? event.target : null;
    if (target && target.closest("#kchatAiSendButton")) sendAiFromLauncher(event);
  }, true);

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