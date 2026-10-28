const go = document.getElementById("go"), pw = document.getElementById("pw"), err = document.getElementById("err");
async function login() {
  err.textContent = "";
  const r = await fetch("/api/login", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json", "X-IDPS": "1" }, body: JSON.stringify({ password: pw.value }) });
  if (r.ok) { location.href = "/"; return; }
  let m = "Could not sign in."; try { m = (await r.json()).error || m; } catch (e) { /* no body */ }
  err.textContent = m;
}
go.addEventListener("click", login);
pw.addEventListener("keydown", e => { if (e.key === "Enter") login(); });
