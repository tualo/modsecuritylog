Ext.define('Tualo.modsecuritylog.lazy.models.Panel', {
    extend: 'Ext.app.ViewModel',
    alias: 'viewmodel.tualo_modsecuritylog_panel',
    data: {
        limit: 500,
        logfile: '',
        selectedEntry: null
    },
    formulas: {
        detailHtml: function (get) {
            let entry = get('selectedEntry');
            if (!entry) {
                return '<div style="padding:12px;color:#888;">Eintrag auswählen, um Details zu sehen.</div>';
            }
            let esc = Ext.String.htmlEncode,
                html = '<div style="padding:12px;font-size:12px;">';
            html += '<table style="border-spacing:0 2px;">';
            let row = function (label, value) {
                if (Ext.isEmpty(value)) return '';
                return '<tr><td style="color:#888;padding-right:12px;white-space:nowrap;vertical-align:top;">'
                    + esc(label) + '</td><td>' + value + '</td></tr>';
            };
            html += row('Zeit', esc(entry.get('timestamp')));
            html += row('Unique-ID', esc(entry.get('unique_id')));
            html += row('Client', esc(entry.get('client_ip')));
            html += row('Host', esc(entry.get('host')));
            html += row('Request', esc(entry.get('method') + ' ' + entry.get('uri')));
            html += row('Referer', esc(entry.get('referer')));
            html += row('User-Agent', esc(entry.get('user_agent')));
            html += row('HTTP-Status', esc(entry.get('status')));
            html += row('Engine-Mode', esc(entry.get('engine_mode')));
            html += row('Blockiert', entry.get('intercepted')
                ? '<span style="color:#c0392b;font-weight:bold;">ja</span>' : 'nein');
            if (!Ext.isEmpty(entry.get('inbound_score'))) {
                html += row('Anomaly-Score', esc(entry.get('inbound_score')));
            }
            html += '</table>';

            let messages = entry.get('messages') || [];
            messages.forEach(function (m) {
                html += '<div style="margin-top:10px;padding:8px;border:1px solid #ddd;border-radius:4px;">';
                html += '<div><b>' + (m.id ? ('Regel ' + esc(m.id)) : 'Meldung') + '</b>'
                    + (m.severity ? ' <span style="color:#c0392b;">[' + esc(m.severity) + ']</span>' : '')
                    + '</div>';
                if (m.msg) html += '<div style="margin-top:4px;">' + esc(m.msg) + '</div>';
                if (m.data) html += '<div style="margin-top:4px;color:#555;">Daten: ' + esc(m.data) + '</div>';
                if (m.file) html += '<div style="margin-top:4px;color:#888;">' + esc(m.file) + (m.line ? (':' + esc(m.line)) : '') + '</div>';
                if (m.tags && m.tags.length > 0) {
                    html += '<div style="margin-top:4px;">' + m.tags.map(function (t) {
                        return '<span style="display:inline-block;background:#eee;border-radius:3px;padding:1px 6px;margin:1px 3px 1px 0;">' + esc(t) + '</span>';
                    }).join('') + '</div>';
                }
                html += '</div>';
            });
            html += '</div>';
            return html;
        }
    },
    stores: {
        entries: {
            type: 'json',
            autoLoad: false,
            fields: [
                { name: 'timestamp', type: 'string' },
                { name: 'unique_id', type: 'string' },
                { name: 'client_ip', type: 'string' },
                { name: 'method', type: 'string' },
                { name: 'uri', type: 'string' },
                { name: 'host', type: 'string' },
                { name: 'referer', type: 'string' },
                { name: 'user_agent', type: 'string' },
                { name: 'status' },
                { name: 'intercepted', type: 'boolean' },
                { name: 'engine_mode', type: 'string' },
                { name: 'inbound_score' },
                { name: 'rule_ids' },
                { name: 'max_severity', type: 'string' },
                { name: 'messages' }
            ],
            proxy: {
                type: 'ajax',
                url: './modsecuritylog/read',
                reader: {
                    type: 'json',
                    rootProperty: 'data'
                }
            }
        }
    }
});
