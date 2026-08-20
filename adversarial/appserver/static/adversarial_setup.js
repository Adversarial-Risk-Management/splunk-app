/*
 * Setup page logic for the Adversarial app.
 *
 * The page reads and writes one entry in the Splunk secret store:
 *   realm "adversarial", user "config"
 * The entry holds a JSON object with the API URL, the client ID and the client
 * secret. Splunk encrypts the value on disk.
 *
 * The code calls the Splunk management API through the proxy that Splunk Web
 * offers at /splunkd/__raw. It uses no library, so the page keeps working
 * across Splunk versions.
 */
(function () {
    'use strict';

    var APP = 'adversarial';
    var REALM = 'adversarial';
    var CONFIG_ENTRY = encodeURIComponent(REALM + ':config:');
    var TOKEN_CACHE_ENTRY = encodeURIComponent(REALM + ':token_cache:');
    var PASSWORDS_PATH = '/servicesNS/nobody/' + APP + '/storage/passwords';

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
     * secret is never sent back to the page. */
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
            var config = {};
            try {
                config = JSON.parse(result.data.entry[0].content.clear_password);
            } catch (error) {
                setStatus('error', 'The stored settings are not readable. Save them again.');
                return;
            }
            element('adversarial-base-url').value = config.base_url || '';
            element('adversarial-client-id').value = config.client_id || '';
            setStatus('ok', 'The app is set up. Client ID: ' + (config.client_id || 'unknown') +
                '. Leave the secret empty to keep the stored secret.');
        }).catch(function (error) {
            setStatus('error', 'Could not reach the Splunk management API: ' + error);
        });
    }

    /* Write the entry. A missing entry needs a create, so an update that
     * returns 404 falls back to a create. */
    function writeSecret(entry, username, value) {
        return request('POST', PASSWORDS_PATH + '/' + entry, { password: value })
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

        setStatus('warn', 'Saving...');

        /* An empty secret box means "keep the stored secret", so read the
         * current value first. */
        request('GET', PASSWORDS_PATH + '/' + CONFIG_ENTRY).then(function (result) {
            var stored = {};
            if (result.ok) {
                try { stored = JSON.parse(result.data.entry[0].content.clear_password); }
                catch (error) { stored = {}; }
            }
            var secret = clientSecret || stored.client_secret;
            if (!secret) {
                setStatus('error', 'Enter the client secret.');
                return null;
            }
            var value = JSON.stringify({
                base_url: baseUrl, client_id: clientId, client_secret: secret
            });
            return writeSecret(CONFIG_ENTRY, 'config', value).then(function () {
                /* New credentials make the cached token pair useless. */
                return request('DELETE', PASSWORDS_PATH + '/' + TOKEN_CACHE_ENTRY);
            }).then(function () {
                element('adversarial-client-secret').value = '';
                setStatus('ok', 'The settings are saved. Splunk keeps the secret encrypted.');
            });
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
