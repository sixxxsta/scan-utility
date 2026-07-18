async function refreshStatus() {
  try {
    const res = await fetch("/api/status");
    const data = await res.json();
    const el = document.getElementById("statusLine");
    if (!el) return;
    el.textContent = data.running
      ? `Running: ${data.message || "..."}`
      : "Idle";
  } catch (_) {}
}

document.getElementById("scanBtn")?.addEventListener("click", async () => {
  const btn = document.getElementById("scanBtn");
  btn.disabled = true;
  try {
    await fetch("/api/scan", { method: "POST" });
    await refreshStatus();
    setTimeout(() => location.reload(), 1500);
  } catch (e) {
    alert("Failed to start scan: " + e);
  } finally {
    btn.disabled = false;
  }
});

setInterval(refreshStatus, 3000);
