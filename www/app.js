(() => {
  "use strict";

  const endpoint = "/cgi-bin/n300vpn";
  const token = document.querySelector('meta[name="n300vpn-token"]').content;
  const app = document.getElementById("app");
  const message = document.getElementById("message");
  const bestSection = document.getElementById("best-section");
  const bestNodesRoot = document.getElementById("best-nodes");
  const subscriptionNodesRoot = document.getElementById("subscription-nodes");
  const repositoryNodesRoot = document.getElementById("repository-nodes");
  const statusKeys = ["mode", "active", "engine", "routes", "watchdog", "updating", "selected", "autostart"];
  const settingsDialog = document.getElementById("path-dialog");
  const sourceDialog = document.getElementById("source-dialog");
  const addSubscriptionDialog = document.getElementById("add-subscription-dialog");
  const subscriptionActionsDialog = document.getElementById("subscription-actions-dialog");
  const pathForm = document.getElementById("path-form");
  const subscriptionForm = document.getElementById("subscription-form");
  const subscriptionHeader = document.getElementById("subscription-header");
  let busy = false;
  let pollTimer = 0;
  let nodesSignature = "";
  let pathDirty = false;
  let pressedButton = null;
  let lastStatus = null;
  let subscriptionPresent = false;
  let wasUpdating = false;
  let wasRanking = false;

  const statusValues = {
    mode: { off: "Выключен", on: "Включен", pending: "Проверка подключения", local: "Локальная проверка" },
    active: { none: "Не выбран" },
    engine: { stopped: "Остановлен", running: "Работает" },
    routes: { off: "Не используется", on: "Используется" },
    watchdog: { stopped: "Остановлено", running: "Работает" },
    updating: { no: "Нет", yes: "Идёт" },
    autostart: { off: "Прямой интернет", on: "Восстановить VPN" }
  };

  function displayStatus(key, value, nodes) {
    if (key === "active" && value && value !== "none") return nodes.find((node) => node.id === value)?.label || value;
    return statusValues[key]?.[value] ?? value ?? "Неизвестно";
  }

  function setMessage(text, isError = false) {
    message.textContent = text;
    message.hidden = !text;
    message.classList.toggle("error", isError);
  }

  function setButtonLabel(button, text) {
    if (!button) return;
    button.dataset.label = text;
    if (!busy || button !== pressedButton) button.textContent = text;
  }

  function applyButtonStates() {
    const backgroundBusy = lastStatus?.updating === "yes" || lastStatus?.ranking === "yes";
    const blockedActions = new Set(["refresh", "rank-youtube", "enable", "youtube", "probe", "add-subscription", "delete-subscription"]);
    document.querySelectorAll("button").forEach((button) => {
      if (!button.dataset.label) button.dataset.label = button.textContent;
      button.textContent = busy && button === pressedButton ? (button.dataset.pending || "Выполняется…") : button.dataset.label;
      const action = button.value || button.dataset.action;
      const cannotDelete = action === "delete-subscription" && lastStatus?.mode !== "off";
      button.disabled = busy || button.dataset.connected === "yes" || button.dataset.unavailable === "yes" || cannotDelete ||
        (backgroundBusy && blockedActions.has(action));
    });
  }

  function setBusy(value, button) {
    busy = value;
    pressedButton = value ? button : null;
    app.setAttribute("aria-busy", value ? "true" : "false");
    applyButtonStates();
  }

  function makeHidden(name, value) {
    const input = document.createElement("input");
    input.type = "hidden";
    input.name = name;
    input.value = value;
    return input;
  }

  function makeAction(label, action, id, className, pending) {
    const form = document.createElement("form");
    form.method = "post";
    form.append(makeHidden("token", token));
    if (id) form.append(makeHidden("id", id));
    const button = document.createElement("button");
    button.type = "submit";
    button.name = "action";
    button.value = action;
    button.textContent = label;
    button.dataset.pending = pending;
    if (className) button.className = className;
    form.append(button);
    return form;
  }

  function pingInfo(value) {
    const latency = Number(value || 999999);
    if (latency <= 120) return ["ping-good", "хороший отклик"];
    if (latency <= 300) return ["ping-medium", "средний отклик"];
    return ["ping-slow", "высокий отклик"];
  }

  function startupInfo(value, target) {
    const duration = Number(value || 999999);
    const className = duration <= 1000 ? "ping-good" : duration <= 2000 ? "ping-medium" : "ping-slow";
    return [className, `Холодная проверка ${target} через новый VPN-туннель`];
  }

  function makeBadge(text, className, title) {
    const badge = document.createElement("span");
    badge.className = className;
    badge.textContent = text;
    if (title) badge.title = title;
    return badge;
  }

  function makeNodeCard(node, active, bestResult) {
    const article = document.createElement("article");
    article.className = `node${node.id === active ? " active" : ""}${bestResult ? " best-result" : ""}`;
    article.dataset.nodeId = node.id;
    const details = document.createElement("div");
    details.className = "node-details";
    const name = document.createElement("div");
    name.className = "name";
    name.append(document.createTextNode(node.label));
    if (node.youtube_best) name.append(document.createTextNode(" "), makeBadge("№1 для YouTube", "winner-badge"));
    const meta = document.createElement("div");
    meta.className = "meta";
    const isSubscription = node.source === "crunch";
    meta.append(makeBadge(isSubscription ? "Моя подписка" : "Репозиторий", `source-badge ${isSubscription ? "subscription" : "repository"}`));
    const endpointPing = document.createElement("span");
    const [endpointClass, endpointTitle] = pingInfo(node.latency);
    endpointPing.append("Отклик ", makeBadge(`${node.latency} мс`, `ping-badge ${endpointClass}`, endpointTitle));
    const protocol = document.createElement("span");
    protocol.textContent = `${node.protocol.toUpperCase()} · ${node.transport}/${node.security}`;
    const address = document.createElement("span");
    address.textContent = `${node.server}:${node.port}`;
    meta.append(endpointPing, protocol, address);
    if (node.youtube_score) {
      const pageCheck = document.createElement("span");
      const [pageClass, pageTitle] = startupInfo(node.youtube_page, "страницы YouTube");
      pageCheck.append("YouTube: страница ", makeBadge(`${node.youtube_page} мс`, `ping-badge ${pageClass}`, pageTitle));
      const mediaCheck = document.createElement("span");
      const [mediaClass, mediaTitle] = startupInfo(node.youtube_media, "видеосети Googlevideo");
      mediaCheck.append("видеосеть ", makeBadge(`${node.youtube_media} мс`, `ping-badge ${mediaClass}`, mediaTitle));
      meta.append(pageCheck, mediaCheck);
    }
    details.append(name, meta);
    const actions = document.createElement("div");
    actions.className = "actions";
    const connectAction = makeAction(node.id === active ? "Подключено" : "Подключить", "enable", node.id, "", "Подключение…");
    if (node.id === active) connectAction.querySelector("button").dataset.connected = "yes";
    actions.append(connectAction, makeAction("Проверить YouTube", "youtube", node.id, "secondary", "Проверка YouTube…"), makeAction("Проверить сеть", "probe", node.id, "secondary", "Проверка…"));
    article.append(details, actions);
    return article;
  }

  function renderNodeList(root, nodes, emptyText, active, bestResult = false, allowAdd = false) {
    root.replaceChildren();
    if (!nodes.length) {
      const empty = document.createElement("div");
      empty.className = "note empty-state";
      empty.textContent = emptyText;
      if (allowAdd) {
        const add = document.createElement("button");
        add.type = "button";
        add.className = "secondary";
        add.dataset.openSubscription = "";
        add.dataset.action = "add-subscription";
        add.textContent = "Добавить подписку";
        empty.append(document.createElement("br"), add);
      }
      root.append(empty);
      return;
    }
    nodes.forEach((node) => root.append(makeNodeCard(node, active, bestResult)));
  }

  function renderNodes(nodes, active, subscription) {
    subscriptionPresent = Boolean(subscription?.present);
    const subscriptionNodes = subscriptionPresent ? nodes.filter((node) => node.source === "crunch") : [];
    const repositoryNodes = nodes.filter((node) => node.source !== "crunch");
    const bestNodes = nodes.filter((node) => node.youtube_score).sort((left, right) =>
      Number(left.youtube_score) - Number(right.youtube_score) || Number(left.latency) - Number(right.latency));
    const signature = JSON.stringify([nodes, active, subscriptionPresent]);
    document.getElementById("subscription-count").textContent = String(subscriptionNodes.length);
    document.getElementById("repository-count").textContent = String(repositoryNodes.length);
    document.getElementById("best-count").textContent = String(bestNodes.length);
    document.getElementById("subscription-menu").hidden = !subscriptionPresent;
    document.getElementById("subscription-section").dataset.subscriptionPresent = subscriptionPresent ? "yes" : "no";
    document.getElementById("subscription-description").textContent = subscriptionPresent ? "Серверы из добавленной вами ссылки. Нажмите правой кнопкой для управления." : "Добавьте свою ссылку, чтобы серверы появились здесь.";
    const subscriptionRank = document.getElementById("rank-subscription");
    subscriptionRank.dataset.unavailable = subscriptionNodes.length ? "no" : "yes";
    setButtonLabel(subscriptionRank, `Моя подписка · ${subscriptionNodes.length} доступных`);
    const repositoryRank = document.getElementById("rank-repository");
    repositoryRank.dataset.unavailable = repositoryNodes.length ? "no" : "yes";
    setButtonLabel(repositoryRank, `Репозиторий igareck · ${repositoryNodes.length} доступных`);
    const rankButton = document.getElementById("rank-button");
    rankButton.dataset.unavailable = nodes.length ? "no" : "yes";
    setButtonLabel(document.getElementById("open-add-subscription"), subscriptionPresent ? "Заменить подписку" : "Добавить подписку");
    bestSection.hidden = !bestNodes.length;
    if (signature === nodesSignature) {
      document.querySelectorAll("[data-node-id]").forEach((node) => node.classList.toggle("active", node.dataset.nodeId === active));
      applyButtonStates();
      return;
    }
    nodesSignature = signature;
    renderNodeList(bestNodesRoot, bestNodes, "", active, true);
    renderNodeList(subscriptionNodesRoot, subscriptionNodes, subscriptionPresent ? "В подписке пока нет ответивших совместимых серверов." : "Подписка ещё не добавлена.", active, false, !subscriptionPresent);
    renderNodeList(repositoryNodesRoot, repositoryNodes, "Серверы репозитория ещё не загружены. Нажмите «Обновить списки».", active);
    applyButtonStates();
  }

  function renderPaths(paths) {
    paths.forEach((path) => {
      const checkbox = pathForm?.querySelector(`[name="path_${path.id}"]`);
      if (checkbox && (!settingsDialog.open || !pathDirty)) checkbox.checked = path.selected;
      const target = document.querySelector(`[data-path-state="${path.id}"]`);
      if (!target) return;
      const connection = path.id === "wifi" ? (path.link === "up" ? "радио включено" : path.link === "down" ? "радио выключено" : "состояние неизвестно") : (path.link === "up" ? "подключён" : path.link === "down" ? "отключён" : "состояние неизвестно");
      const details = [connection, path.speed, path.duplex === "full" ? "полный дуплекс" : "", `${path.devices} устр.`].filter(Boolean);
      target.textContent = details.join(" · ");
    });
  }

  function render(data) {
    const nodes = data.nodes || [];
    lastStatus = data.status;
    statusKeys.forEach((key) => {
      const target = document.getElementById(`status-${key}`);
      if (target) target.textContent = displayStatus(key, data.status[key], nodes);
    });
    const stats = data.stats || {};
    document.getElementById("import-note").textContent = `Найдено серверов VLESS: ${stats.total_vless || 0}; подходят этому роутеру: ${stats.unique_compatible || 0}; быстро ответили: ${stats.reachable || data.status.selected || 0}; Reality: ${stats.reality || 0}; Vision: ${stats.vision || 0}; gRPC: ${stats.grpc || 0}.`;
    renderPaths(data.paths || []);
    renderNodes(nodes, data.status.active, data.subscription || { present: false });
    document.getElementById("disable-vpn-form").hidden = !["on", "pending", "local"].includes(data.status.mode);
    applyButtonStates();
    const updating = data.status.updating === "yes";
    const ranking = data.status.ranking === "yes";
    if (updating) {
      const done = Number(data.status.scan_done || 0);
      const total = Number(data.status.scan_total || 0);
      setMessage(total > 0 ? `Проверяю совместимые серверы: ${Math.min(done + 1, total)} из ${total}. Они проверяются по одному, чтобы не перегружать роутер.` : "Загружаю подписки и готовлю списки серверов…");
    } else if (ranking) {
      const current = nodes.find((node) => node.id === data.status.youtube_testing);
      const sourceLabel = data.status.youtube_source === "crunch" ? "моя подписка" : "репозиторий igareck";
      setMessage(`Проверяю YouTube (${sourceLabel}): ${Math.min(Number(data.status.youtube_done || 0) + 1, Number(data.status.youtube_total || 0))} из ${data.status.youtube_total || "?"}${current ? ` · ${current.label}` : ""}.`);
    } else if (wasUpdating) {
      setMessage(`Списки обновлены. Доступно серверов: ${data.status.selected || 0}.`);
    } else if (wasRanking) {
      const best = nodes.find((node) => node.id === data.status.youtube_best);
      const sourceLabel = data.status.youtube_source === "crunch" ? "вашей подписки" : "репозитория igareck";
      setMessage(best ? `Проверка ${sourceLabel} завершена. Лучший сервер: ${best.label} · страница ${best.youtube_page} мс · видеосеть ${best.youtube_media} мс. Все успешные результаты показаны выше.` : `Проверка ${sourceLabel} завершена, но ни один сервер не смог открыть YouTube и видеосеть.`, !best);
    }
    wasUpdating = updating;
    wasRanking = ranking;
  }

  function friendlyResult(action, data, source) {
    const raw = data.message || "Готово";
    const latency = raw.match(/latency_ms=(\d+)/)?.[1];
    const pageMs = raw.match(/page_ms=(\d+)/)?.[1];
    const mediaMs = raw.match(/media_ms=(\d+)/)?.[1];
    if (!data.ok) {
      if (/already running|still running|уже идёт/i.test(raw)) return "Проверка серверов уже идёт. Дождитесь её завершения — прогресс показан выше.";
      if (/no reachable servers/i.test(raw)) return "Пока нет доступных серверов. Сначала обновите списки.";
      if (/handshake failed|response header read failed/i.test(raw)) return "Этот сервер доступен, но не смог открыть YouTube. Попробуйте другой или запустите автоматический выбор лучших серверов.";
      if (/disable VPN before removing subscription/i.test(raw)) return "Перед удалением подписки выключите VPN, чтобы текущие устройства не потеряли соединение.";
      return raw;
    }
    if (action === "youtube") return `YouTube и видеосеть доступны через этот сервер${pageMs && mediaMs ? ` · страница ${pageMs} мс · видеосеть ${mediaMs} мс` : ""}. Это две отдельные холодные проверки, а не пинг.`;
    if (action === "rank-youtube") return `Проверка серверов из ${source === "crunch" ? "вашей подписки" : "репозитория igareck"} запущена. Успешные результаты появятся в разделе «Лучшие серверы».`;
    if (action === "add-subscription") return "Подписка сохранена на USB. Серверы загружаются и проверяются по одному.";
    if (action === "delete-subscription") return "Подписка и её сохранённый список удалены. Серверы репозитория обновляются.";
    if (action === "enable") return "Туннель запущен. Проверяю интернет через него; без подтверждения прямое соединение восстановится автоматически.";
    if (action === "confirm") return "VPN подключён и проверен браузером. Автозапуск пока оставлен выключенным.";
    if (action === "disable") return "VPN выключен. Используется прямой интернет.";
    if (action === "refresh") return "Обновление списков запущено. Новые результаты появятся здесь автоматически.";
    if (action === "set-paths") return "Настройка LAN и Wi-Fi сохранена. Новые соединения уже используют выбранный путь.";
    if (action === "probe") return `Сервер доступен${latency ? ` · ${latency} мс` : ""}.`;
    return raw;
  }

  async function readJson(url, options) {
    const response = await fetch(url, options);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return response.json();
  }

  async function postAction(action) {
    const body = new URLSearchParams({ token, api: "1", action });
    return readJson(endpoint, {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8" },
      body
    });
  }

  async function verifyAndConfirmActivation() {
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 9000);
    try {
      await fetch(`https://www.youtube.com/generate_204?n300vpn=${Date.now()}`, {
        mode: "no-cors",
        cache: "no-store",
        signal: controller.signal
      });
      const confirmed = await postAction("confirm");
      render(confirmed);
      setMessage(friendlyResult("confirm", confirmed), !confirmed.ok);
      return confirmed.ok;
    } catch (_error) {
      const disabled = await postAction("disable").catch(() => null);
      if (disabled) render(disabled);
      setMessage("Проверка через YouTube не прошла. VPN отменён, прямой интернет восстановлен.", true);
      return false;
    } finally {
      clearTimeout(timeout);
    }
  }

  async function poll() {
    clearTimeout(pollTimer);
    try {
      const data = await readJson(`${endpoint}?api=status&_=${Date.now()}`, { headers: { Accept: "application/json" }, cache: "no-store" });
      render(data);
      pollTimer = window.setTimeout(poll, busy || data.status.updating === "yes" || data.status.ranking === "yes" ? 2000 : 7000);
    } catch (_error) {
      pollTimer = window.setTimeout(poll, 5000);
    }
  }

  function openDialog(dialog) {
    if (!dialog) return;
    if (typeof dialog.showModal === "function") dialog.showModal();
    else dialog.setAttribute("open", "");
  }

  document.addEventListener("submit", async (event) => {
    const form = event.target.closest("form");
    if (!form || busy) return;
    event.preventDefault();
    const button = event.submitter || form.querySelector("button[type=submit],button:not([type])");
    const body = new URLSearchParams(new FormData(form));
    body.set("token", token);
    body.set("api", "1");
    if (button?.name) body.set(button.name, button.value);
    const action = body.get("action");
    const source = body.get("source");
    setBusy(true, button);
    setMessage(button?.dataset.pending || "Выполняется…");
    poll();
    try {
      const data = await readJson(endpoint, { method: "POST", headers: { Accept: "application/json", "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8" }, body });
      render(data);
      setMessage(friendlyResult(action, data, source), !data.ok);
      if (action === "enable" && data.ok) await verifyAndConfirmActivation();
      if (action === "set-paths" && data.ok && settingsDialog.open) settingsDialog.close();
      if (action === "rank-youtube" && data.ok && sourceDialog.open) sourceDialog.close();
      if (action === "add-subscription" && data.ok && addSubscriptionDialog.open) {
        addSubscriptionDialog.close();
        subscriptionForm.reset();
      }
      if (action === "delete-subscription" && data.ok && subscriptionActionsDialog.open) subscriptionActionsDialog.close();
    } catch (error) {
      setMessage(`Связь с панелью потеряна: ${error.message}. Состояние будет проверено повторно.`, true);
    } finally {
      setBusy(false, null);
      poll();
    }
  });

  document.addEventListener("click", (event) => {
    const closeButton = event.target.closest("[data-close-dialog]");
    if (closeButton) document.getElementById(closeButton.dataset.closeDialog)?.close();
    if (event.target.closest("[data-open-subscription]")) openDialog(addSubscriptionDialog);
  });
  [settingsDialog, sourceDialog, addSubscriptionDialog, subscriptionActionsDialog].forEach((dialog) => dialog?.addEventListener("click", (event) => { if (event.target === dialog) dialog.close(); }));
  document.getElementById("open-settings")?.addEventListener("click", () => { pathDirty = false; openDialog(settingsDialog); });
  pathForm?.addEventListener("change", () => { pathDirty = true; });
  document.getElementById("rank-button")?.addEventListener("click", () => openDialog(sourceDialog));
  document.getElementById("open-add-subscription")?.addEventListener("click", () => openDialog(addSubscriptionDialog));
  document.getElementById("subscription-menu")?.addEventListener("click", () => { if (subscriptionPresent) openDialog(subscriptionActionsDialog); });
  subscriptionHeader?.addEventListener("contextmenu", (event) => { if (subscriptionPresent) { event.preventDefault(); openDialog(subscriptionActionsDialog); } });
  subscriptionHeader?.addEventListener("keydown", (event) => {
    if (subscriptionPresent && (event.key === "ContextMenu" || (event.shiftKey && event.key === "F10"))) {
      event.preventDefault();
      openDialog(subscriptionActionsDialog);
    }
  });
  document.getElementById("replace-subscription")?.addEventListener("click", () => { subscriptionActionsDialog.close(); openDialog(addSubscriptionDialog); });
  poll();
})();
