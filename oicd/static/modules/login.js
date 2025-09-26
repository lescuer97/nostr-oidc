// modules/login.js

export async function signNostrEvent(event) {
  if (!window.nostr) {
    throw Error("window nostr is not set. You need a NIP-07 extension");
  }
  return await window.nostr.signEvent(event);
}

export function initLogin() {
  const loginContainer = document.getElementById("loginContainer");
  if (!loginContainer) return;

  loginContainer.addEventListener("submit", async (e) => {
    e.preventDefault();

    const eventToSign = {
      created_at: Math.floor(Date.now() / 1000),
      kind: 27235,
      tags: [],
      content: loginContainer.nonce,
    };

    try {
      const signedEvent = await signNostrEvent(eventToSign);
      let loginUrl = "/login"
        if (loginContainer?.dataset?.admin === 'true') {
            loginUrl = "/admin/login"
        }
      const res = await fetch(new Request(loginUrl, {
        method: "POST",
        body: JSON.stringify(signedEvent),
      }));

      if (res.ok) {
        if (loginContainer?.dataset?.admin === 'true') {
            window.location.href = "/admin";
        }else{
            window.location.href = "/";
        }
      } else {
        const targetHeader = res.headers.get("HX-RETARGET");
        if (window.htmx && targetHeader) {
          const text = await res.text();
          window.htmx.swap(`#${targetHeader}`, text, { swapStyle: "innerHTML" });
        }
      }
    } catch (err) {
      console.log("Login error", err);
    }
  });
}
