SUPPORT — modern UI replacement for Grandpa Connect

Replace exactly these three files in your existing GitHub repository:
  dashboard.html
  index.html
  viewer.html

Do NOT replace server.js or package.json. Keep your Render environment variables.

Install: Open each matching filename on GitHub, click Edit (pencil), select all, paste full replacement content, and Commit changes. Do not upload them under new names.

Test: After Render finishes deploying, create a NEW invitation from /dashboard.html, open the screen-sharing link on a Windows/Mac Chrome/Edge, and the viewer link on your phone. Check connection and Stop sharing.

This redesign keeps the existing WebRTC signaling, adaptive quality, TURN configuration flow, and reconnect code as present in the files used to build it. It cannot remove the browser share permission prompt or keep sharing after closing the tab.

Source note: index.html and viewer.html were based on the prior working local full replacement files in this conversation. dashboard.html follows the invitation endpoint and payload inspected on GitHub. Live device integration has not been verified.
