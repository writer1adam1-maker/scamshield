/**
 * ScamShield Options Page
 * Manages API key and feature toggles in chrome.storage.sync
 */

(function () {
  'use strict';

  var apiKeyInput = document.getElementById('apiKeyInput');
  var saveBtn     = document.getElementById('saveBtn');
  var clearBtn    = document.getElementById('clearBtn');
  var keyStatus   = document.getElementById('keyStatus');
  var toggleEnabled  = document.getElementById('toggleEnabled');
  var toggleBlock    = document.getElementById('toggleBlock');
  var toggleWarnings = document.getElementById('toggleWarnings');
  var statScanned   = document.getElementById('statScanned');
  var statThreats   = document.getElementById('statThreats');
  var statBlocked   = document.getElementById('statBlocked');

  // Load saved settings
  chrome.storage.sync.get(['ss_api_key', 'ss_enabled', 'ss_block_clicks', 'ss_warnings_disabled'], function (data) {
    if (data.ss_api_key) apiKeyInput.value = data.ss_api_key;
    setToggle(toggleEnabled, data.ss_enabled !== false);
    setToggle(toggleBlock, data.ss_block_clicks !== false);
    setToggle(toggleWarnings, data.ss_warnings_disabled === true);
  });

  // Load session stats
  chrome.storage.session.get(['ss_stat_scanned', 'ss_stat_threats', 'ss_stat_blocked'], function (data) {
    statScanned.textContent = data.ss_stat_scanned || 0;
    statThreats.textContent = data.ss_stat_threats || 0;
    statBlocked.textContent = data.ss_stat_blocked || 0;
  });

  // Save API key
  saveBtn.addEventListener('click', function () {
    var key = apiKeyInput.value.trim();
    if (!key) {
      showStatus('keyStatus', 'Enter an API key first.', 'err');
      return;
    }
    if (!key.startsWith('ss_live_') && !key.startsWith('ss_test_')) {
      showStatus('keyStatus', 'Key must start with ss_live_ or ss_test_', 'err');
      return;
    }
    if (key.length < 24) {
      showStatus('keyStatus', 'Key looks too short. Check your key in Settings.', 'err');
      return;
    }
    chrome.storage.sync.set({ ss_api_key: key }, function () {
      showStatus('keyStatus', '✓ API key saved. Link scanning will use your account quota.', 'ok');
    });
  });

  // Clear API key
  clearBtn.addEventListener('click', function () {
    chrome.storage.sync.remove('ss_api_key', function () {
      apiKeyInput.value = '';
      showStatus('keyStatus', 'API key removed. Scanning in anonymous mode.', 'info');
    });
  });

  // Toggles
  toggleEnabled.addEventListener('click', function () {
    var next = !toggleEnabled.classList.contains('on');
    setToggle(toggleEnabled, next);
    chrome.storage.sync.set({ ss_enabled: next });
  });

  toggleBlock.addEventListener('click', function () {
    var next = !toggleBlock.classList.contains('on');
    setToggle(toggleBlock, next);
    chrome.storage.sync.set({ ss_block_clicks: next });
  });

  toggleWarnings.addEventListener('click', function () {
    var next = !toggleWarnings.classList.contains('on');
    setToggle(toggleWarnings, next);
    chrome.storage.sync.set({ ss_warnings_disabled: next });
  });

  // Helpers
  function setToggle(el, on) {
    if (on) el.classList.add('on');
    else    el.classList.remove('on');
  }

  function showStatus(id, msg, type) {
    var el = document.getElementById(id);
    el.textContent = msg;
    el.className = 'status ' + type;
    setTimeout(function () { el.className = 'status'; }, 4000);
  }
})();
