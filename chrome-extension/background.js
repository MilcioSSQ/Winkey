// Only detects that a login form exists and shows a generic notification -
// deliberately does NOT decrypt or look up matching credentials here. The
// vault key only ever lives in the popup's memory / chrome.storage.session;
// duplicating decryption logic into the background worker just to enrich
// this notification isn't worth the added attack surface. Open the popup to
// see (and one-click fill) any matching saved entry for the active tab.
chrome.runtime.onMessage.addListener((request) => {
  if (request.action === 'formDetected') {
    chrome.notifications.create({
      type: 'basic',
      title: 'Winkey',
      message: 'Login-Formular erkannt. Öffne Winkey, um gespeicherte Zugangsdaten auf dieser Seite auszufüllen.',
    });
  }
});

chrome.runtime.onInstalled.addListener(({ reason }) => {
  if (reason === 'install') {
    chrome.notifications.create({
      type: 'basic',
      title: 'Willkommen bei Winkey',
      message: 'Klicke auf das Symbol in der Toolbar, um dich anzumelden und loszulegen.',
    });
  }
});
