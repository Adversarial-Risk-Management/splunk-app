/*
 * Setup page logic for the Adversarial app.
 *
 * The page uses these entries in the Splunk secret store, realm "adversarial":
 *   config               JSON with the API URL and the default client ID
 *   secret_<client ID>   the client secret of that service account
 *   token_<client ID>    the cached token pair, removed when the secret changes
 * Splunk encrypts each value on disk. The page reads only `config`, so the
 * client secret never travels to the browser.
 *
 * The code calls the Splunk management API through the proxy that Splunk Web
 * offers at /splunkd/__raw. It uses no library, so the page keeps working
 * across Splunk versions.
 */
(function () {
    'use strict';

    var APP = 'adversarial';
    var REALM = 'adversarial';
    var CONFIG_ENTRY = entry('config');
    var PASSWORDS_PATH = '/servicesNS/nobody/' + APP + '/storage/passwords';

    /* The stored settings, as the last load read them. */
    var stored = {};

    function entry(username) {
        return encodeURIComponent(REALM + ':' + username + ':');
    }

    /* The page URL looks like /en-US/app/<app>/<view>, so the part before
     * "/app/" is the prefix that the REST proxy needs. */
    function urlPrefix() {
        var path = window.location.pathname;
        var index = path.indexOf('/app/');
        return index > 0 ? path.slice(0, index) : '';
    }

    /* Splunk Web rejects a write without this token. The token sits in a
     * cookie whose name ends with the web port. */
    function formKey() {
        var match = document.cookie.match(/splunkweb_csrf_token_\d+=([^;]+)/);
        return match ? decodeURIComponent(match[1]) : '';
    }

    function request(method, path, fields) {
        var url = urlPrefix() + '/splunkd/__raw' + path;
        url += (url.indexOf('?') === -1 ? '?' : '&') + 'output_mode=json';
        var headers = { 'X-Requested-With': 'XMLHttpRequest' };
        var body;
        if (method !== 'GET' && method !== 'DELETE') {
            headers['Content-Type'] = 'application/x-www-form-urlencoded';
            headers['X-Splunk-Form-Key'] = formKey();
            body = Object.keys(fields || {}).map(function (name) {
                return encodeURIComponent(name) + '=' + encodeURIComponent(fields[name]);
            }).join('&');
        } else if (method === 'DELETE') {
            headers['X-Splunk-Form-Key'] = formKey();
        }
        return fetch(url, {
            method: method,
            headers: headers,
            body: body,
            credentials: 'same-origin'
        }).then(function (response) {
            return response.text().then(function (text) {
                var data = null;
                try { data = text ? JSON.parse(text) : null; } catch (error) { data = null; }
                return { status: response.status, ok: response.ok, data: data, text: text };
            });
        });
    }

    function element(id) {
        return document.getElementById(id);
    }

    function setStatus(kind, message) {
        var status = element('adversarial-status');
        if (!status) { return; }
        status.className = 'adversarial-status adversarial-' + kind;
        status.textContent = message;
    }

    /* Show what is stored, so an administrator can confirm the state. The
     * `config` entry holds no secret. An install from version 1.0 still keeps
     * the secret there until the settings are saved again. */
    function load() {
        return request('GET', PASSWORDS_PATH + '/' + CONFIG_ENTRY).then(function (result) {
            if (result.status === 404) {
                setStatus('warn', 'The app is not set up yet. Enter the values and click Save.');
                return;
            }
            if (!result.ok) {
                setStatus('error', 'Could not read the stored settings (HTTP ' + result.status +
                    '). Your Splunk user needs the list_storage_passwords capability.');
                return;
            }
            try {
                stored = JSON.parse(result.data.entry[0].content.clear_password);
            } catch (error) {
                setStatus('error', 'The stored settings are not readable. Save them again.');
                return;
            }
            element('adversarial-base-url').value = stored.base_url || '';
            element('adversarial-client-id').value = stored.client_id || '';
            var note = stored.client_secret ?
                ' Click Save once to move the secret into its own encrypted entry.' :
                ' Leave the secret empty to keep the stored secret.';
            setStatus('ok', 'The app is set up. Client ID: ' + (stored.client_id || 'unknown') +
                '.' + note);
            /* Forget the old combined secret as soon as the page has seen it. */
            stored.legacySecret = stored.client_secret;
            delete stored.client_secret;
        }).catch(function (error) {
            setStatus('error', 'Could not reach the Splunk management API: ' + error);
        });
    }

    /* Write the entry. A missing entry needs a create, so an update that
     * returns 404 falls back to a create. */
    function writeSecret(username, value) {
        return request('POST', PASSWORDS_PATH + '/' + entry(username), { password: value })
            .then(function (result) {
                if (result.ok) { return result; }
                if (result.status !== 404) { return Promise.reject(result.text); }
                return request('POST', PASSWORDS_PATH, {
                    name: username, realm: REALM, password: value
                }).then(function (created) {
                    return created.ok ? created : Promise.reject(created.text);
                });
            });
    }

    /* Remove an entry. A missing entry is fine; any other failure stops the
     * save, because a stale token would keep sending to the old account. */
    function deleteSecret(username) {
        return request('DELETE', PASSWORDS_PATH + '/' + entry(username)).then(function (result) {
            if (result.ok || result.status === 404) { return result; }
            return Promise.reject('HTTP ' + result.status + ' while removing ' + username +
                ': ' + result.text);
        });
    }

    function save() {
        var baseUrl = element('adversarial-base-url').value.trim();
        var clientId = element('adversarial-client-id').value.trim();
        var clientSecret = element('adversarial-client-secret').value.trim();

        if (!baseUrl || !clientId) {
            setStatus('error', 'Enter the API URL and the client ID.');
            return;
        }
        if (baseUrl.indexOf('http://') !== 0 && baseUrl.indexOf('https://') !== 0) {
            setStatus('error', 'The API URL must start with http:// or https://.');
            return;
        }

        if (!/^[A-Za-z0-9_]+$/.test(clientId)) {
            setStatus('error', 'The client ID holds only letters, digits and underscores.');
            return;
        }

        /* An empty secret box keeps the stored secret, which works only for
         * the client ID that is already stored. The page never reads a
         * secret back. */
        var sameClient = clientId === stored.client_id;
        var secret = clientSecret || (sameClient ? stored.legacySecret : '');
        if (!secret && !sameClient) {
            setStatus('error', 'Enter the client secret of ' + clientId + '.');
            return;
        }

        setStatus('warn', 'Saving...');

        /* Write the secret before the config, so the config never names a
         * client ID without a secret. A new secret drops the cached token of
         * that client. */
        var steps = Promise.resolve();
        if (secret) {
            steps = steps.then(function () {
                return writeSecret('secret_' + clientId, secret);
            }).then(function () {
                return deleteSecret('token_' + clientId);
            });
        }
        steps.then(function () {
            return writeSecret('config', JSON.stringify({ base_url: baseUrl, client_id: clientId }));
        }).then(function () {
            /* Version 1.0 kept one token pair for every service account. */
            return deleteSecret('token_cache');
        }).then(function () {
            stored = { base_url: baseUrl, client_id: clientId };
            element('adversarial-client-secret').value = '';
            setStatus('ok', 'The settings are saved. Splunk keeps the secret encrypted.');
        }).catch(function (error) {
            setStatus('error', 'Could not save the settings: ' + error);
        });
    }

    function start() {
        var button = element('adversarial-save');
        if (!button) {
            /* The dashboard HTML panel is not in the page yet. */
            window.setTimeout(start, 200);
            return;
        }
        button.addEventListener('click', save);
        load();
    }

    start();
}());
