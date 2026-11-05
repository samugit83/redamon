// Every route is assembled at runtime, so no complete path appears in this file:
// a static JS parser (katana -jc, jsluice) cannot extract them, and only a
// browser that runs the code and clicks finds them.
(function () {
  function seg() { return '/' + Array.prototype.join.call(arguments, '/'); }
  function api() { return seg.apply(null, ['ap' + 'i', 'v' + 1].concat([].slice.call(arguments))); }

  var app = document.getElementById('app');
  app.textContent = '';
  fetch(api('ses' + 'sion'));

  function button(label, onClick) {
    var b = document.createElement('button');
    b.textContent = label;
    b.onclick = onClick;
    app.appendChild(b);
  }
  button('Items', function () { fetch(api('ite' + 'ms') + '?page=' + 2); });
  button('Preferences', function () { fetch(api('pre' + 'ferences')); });
  button('Export', function () { fetch(api('rep' + 'orts', 'exp' + 'ort') + '?format=' + 'csv'); });
  button('Help', function () { window.location.href = seg('he' + 'lp'); });
})();
