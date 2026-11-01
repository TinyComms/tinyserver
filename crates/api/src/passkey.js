(function () {
  'use strict';

  var root = document.querySelector('main');
  var mode = root.getAttribute('data-mode');
  var state = root.getAttribute('data-state') || '';
  var statusLine = document.getElementById('status');
  var busy = false;
  var cont = '';
  var token = '';

  function $(id) {
    return document.getElementById(id);
  }

  function say(text, bad) {
    statusLine.textContent = text;
    statusLine.className = bad ? 'alert' : 'note';
  }

  function buttons(disabled) {
    var all = root.querySelectorAll('button');
    for (var i = 0; i < all.length; i++) {
      if (all[i].id === 'go') {
        continue;
      }
      all[i].disabled = disabled;
    }
  }

  function fromB64(text) {
    var s = text.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) {
      s += '=';
    }
    var raw = atob(s);
    var bytes = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) {
      bytes[i] = raw.charCodeAt(i);
    }
    return bytes.buffer;
  }

  function toB64(buffer) {
    var bytes = new Uint8Array(buffer);
    var raw = '';
    for (var i = 0; i < bytes.length; i++) {
      raw += String.fromCharCode(bytes[i]);
    }
    return btoa(raw).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  var problems = {
    expired: 'This sign-in expired. Start again from Tiny.',
    invalid: 'That did not work. Try again.',
    invalid_code: 'That recovery code is not valid, or it was already used.',
    invalid_link: 'This link is not valid any more. Ask whoever runs this server for a new one.',
    no_invite: 'This sign-in has no invite, so a new account cannot be made.',
    invite_unusable: 'The invite was used up, has expired, or was withdrawn.',
    credential_taken: 'That passkey is already registered here.',
    banned: 'This account is not allowed in.',
    flagged: 'This passkey was turned off because it looked copied. Use a recovery code.',
    slow_down: 'Too many tries. Wait a minute and try again.',
    busy: 'The server is busy. Try again in a moment.'
  };

  function fail(error) {
    busy = false;
    buttons(false);
    if (error && error.error) {
      say(problems[error.error] || 'Something went wrong. Try again.', true);
    } else if (error && (error.name === 'NotAllowedError' || error.name === 'AbortError')) {
      say('Cancelled. Try again when you are ready.', true);
    } else if (error && error.name === 'InvalidStateError') {
      say('This device already has a passkey for this account.', true);
    } else {
      say('This browser could not use a passkey. Try another browser or device.', true);
    }
  }

  function run(message, work) {
    if (busy) {
      return;
    }
    busy = true;
    buttons(true);
    say(message, false);
    var started;
    try {
      started = work();
    } catch (error) {
      fail(error);
      return;
    }
    started.catch(fail);
  }

  function post(path, body) {
    return fetch(path, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
      credentials: 'omit',
      cache: 'no-store'
    }).then(function (response) {
      return response.json().then(function (json) {
        if (!response.ok) {
          throw json;
        }
        return json;
      });
    });
  }

  function create(options) {
    var key = options.publicKey;
    key.challenge = fromB64(key.challenge);
    key.user.id = fromB64(key.user.id);
    (key.excludeCredentials || []).forEach(function (entry) {
      entry.id = fromB64(entry.id);
    });
    return navigator.credentials.create(options);
  }

  function get(options) {
    var key = options.publicKey;
    key.challenge = fromB64(key.challenge);
    (key.allowCredentials || []).forEach(function (entry) {
      entry.id = fromB64(entry.id);
    });
    return navigator.credentials.get(options);
  }

  function made(credential) {
    return {
      id: credential.id,
      rawId: toB64(credential.rawId),
      type: credential.type,
      extensions: credential.getClientExtensionResults(),
      response: {
        attestationObject: toB64(credential.response.attestationObject),
        clientDataJSON: toB64(credential.response.clientDataJSON)
      }
    };
  }

  function asserted(credential) {
    var response = credential.response;
    return {
      id: credential.id,
      rawId: toB64(credential.rawId),
      type: credential.type,
      extensions: credential.getClientExtensionResults(),
      response: {
        authenticatorData: toB64(response.authenticatorData),
        clientDataJSON: toB64(response.clientDataJSON),
        signature: toB64(response.signature),
        userHandle: response.userHandle ? toB64(response.userHandle) : null
      }
    };
  }

  // The recovery codes, or a notice, and the way on. Nothing here is built from server text
  // except through textContent.
  function showCodes(intro, codes, onGo) {
    $('form').hidden = true;
    $('codes').hidden = false;
    $('codes-intro').textContent = intro;
    var hasCodes = codes && codes.length > 0;
    $('codelist').hidden = !hasCodes;
    $('codes-ack').hidden = !hasCodes;
    if (hasCodes) {
      $('codelist').textContent = codes.join('\n');
    }
    var go = $('go');
    go.disabled = hasCodes;
    var saved = $('saved');
    saved.checked = false;
    saved.onchange = function () {
      go.disabled = !saved.checked;
    };
    go.onclick = function () {
      go.disabled = true;
      onGo();
    };
    say('', false);
    busy = false;
  }

  function leave(path) {
    run('Going back to Tiny…', function () {
      return post(path, { state: state, cont: cont }).then(function (result) {
        location.assign(result.redirect);
      });
    });
  }

  function signIn() {
    run('Waiting for your passkey…', function () {
      return post('/v1/auth/passkey/login/begin', { state: state }).then(function (begun) {
        return get(begun.options).then(function (credential) {
          return post('/v1/auth/passkey/login/finish', {
            state: state,
            cid: begun.cid,
            credential: asserted(credential)
          });
        });
      }).then(function (result) {
        say('Signed in. Going back to Tiny…', false);
        location.assign(result.redirect);
      });
    });
  }

  function signUp() {
    var name = $('name').value.trim();
    if (!name) {
      say('Choose the name other people will see.', true);
      return;
    }
    run('Waiting for your passkey…', function () {
      return post('/v1/auth/passkey/signup/begin', { state: state, display_name: name }).then(function (begun) {
        return create(begun.options).then(function (credential) {
          return post('/v1/auth/passkey/signup/finish', {
            state: state,
            cid: begun.cid,
            credential: made(credential)
          });
        });
      }).then(function (result) {
        cont = result.cont;
        showCodes('Your account is ready. Save these recovery codes somewhere safe, such as a password manager.', result.codes, function () {
          leave('/v1/auth/passkey/continue');
        });
      });
    });
  }

  function recover() {
    var code = $('code').value.trim();
    if (!code) {
      say('Type a recovery code.', true);
      return;
    }
    run('Checking the code…', function () {
      return post('/v1/auth/passkey/recover/begin', { state: state, code: code }).then(function (begun) {
        say('Waiting for your new passkey…', false);
        return create(begun.options).then(function (credential) {
          return post('/v1/auth/passkey/recover/finish', {
            state: state,
            cid: begun.cid,
            code: code,
            credential: made(credential)
          });
        });
      }).then(function (result) {
        cont = result.cont;
        var left = result.codes_left;
        showCodes('Your new passkey is made and that code is used up. You have ' + left + ' recovery code' + (left === 1 ? '' : 's') + ' left. Make a fresh set in Tiny when you can.', [], function () {
          leave('/v1/auth/passkey/continue');
        });
      });
    });
  }

  function claim() {
    run('Waiting for your passkey…', function () {
      return post('/v1/auth/passkey/claim/begin', { token: token }).then(function (begun) {
        return create(begun.options).then(function (credential) {
          return post('/v1/auth/passkey/claim/finish', {
            token: token,
            cid: begun.cid,
            credential: made(credential)
          });
        });
      }).then(function (result) {
        token = '';
        var finish = function () {
          $('codes').hidden = true;
          $('done').hidden = false;
          say('', false);
        };
        if (result.codes && result.codes.length > 0) {
          showCodes('Your passkey is ready. Save these recovery codes somewhere safe, such as a password manager.', result.codes, finish);
        } else {
          $('form').hidden = true;
          finish();
          busy = false;
        }
      });
    });
  }

  function bind(id, handler) {
    var element = $(id);
    if (element) {
      element.addEventListener('click', handler);
    }
  }

  if (!window.PublicKeyCredential || !navigator.credentials) {
    say('This browser cannot use passkeys. Try another browser or device.', true);
    buttons(true);
    return;
  }

  if (mode === 'signin') {
    bind('login', signIn);
    bind('signup', signUp);
    bind('recover', recover);
  } else if (mode === 'claim') {
    // The token is in the address after the #, which the browser never sends anywhere. Read it
    // and take it out of the address bar and history.
    token = location.hash.slice(1);
    if (window.history && history.replaceState) {
      history.replaceState(null, '', location.pathname);
    }
    bind('claim', claim);
    if (!token) {
      $('who').textContent = problems.invalid_link;
    } else {
      post('/v1/auth/passkey/claim/peek', { token: token }).then(function (who) {
        $('who').textContent = 'This makes a passkey for ' + who.name + '.';
        $('server-name').textContent = who.server;
        var mark = $('server-icon');
        if (who.icon) {
          var img = document.createElement('img');
          img.className = 'mark';
          img.id = 'server-icon';
          img.alt = '';
          img.src = who.icon;
          mark.replaceWith(img);
        } else {
          mark.textContent = (who.server.match(/[A-Za-z0-9]/) || ['T'])[0].toUpperCase();
        }
        $('claim').hidden = false;
      }).catch(function () {
        $('who').textContent = problems.invalid_link;
      });
    }
  }
}());
