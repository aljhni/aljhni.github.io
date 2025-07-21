const wafTampers = {
  "FortiWAF": ["space2comment", "charencode", "base64encode", "overlongutf8", "space2dash", "equaltolike"],
  "Cloudflare": ["randomcase", "space2comment", "overlongutf8", "modsecurityversioned", "space2tab", "space2dash"],
  "Akamai": ["randomcase", "equaltolike", "space2comment", "chardoubleencode", "randomcomments", "space2hash"],
  "Barracuda": ["space2comment", "appendnullbyte", "randomcomments", "charencode", "space2dash"],
  "Imperva": ["between", "charencode", "lowercase", "base64encode", "modsecurityversioned"],
  "F5": ["between", "chardoubleencode", "unionalltounion", "multiplespaces", "lowercase"]
};

const buttonsContainer = document.getElementById("waf-buttons");
const tamperList = document.getElementById("tamper-list");

Object.keys(wafTampers).forEach(waf => {
  const button = document.createElement("button");
  button.textContent = waf;
  button.addEventListener("click", () => {
    showTampers(waf);
  });
  buttonsContainer.appendChild(button);
});

function showTampers(waf) {
  tamperList.innerHTML = "";
  wafTampers[waf].forEach(tamper => {
    const li = document.createElement("li");
    li.textContent = tamper;
    tamperList.appendChild(li);
  });
}
