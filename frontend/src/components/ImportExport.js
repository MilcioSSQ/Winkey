import React, { useState, useRef } from 'react';
import axios from 'axios';
import {
  Box, Typography, Paper, Button, Alert, Dialog, DialogTitle, DialogContent, DialogActions,
  List, ListItem, ListItemIcon, ListItemText, LinearProgress, Checkbox, FormControlLabel,
} from '@mui/material';
import { Download as DownloadIcon, Upload as UploadIcon, Description as DescriptionIcon } from '@mui/icons-material';
import { useAuth } from '../contexts/AuthContext';
import { decryptJson, encryptJson } from '../crypto/windkeyCrypto';

export default function ImportExport() {
  const { userKey } = useAuth();
  const fileInputRef = useRef(null);

  const [exportConfirmOpen, setExportConfirmOpen] = useState(false);
  const [exportAck, setExportAck] = useState(false);
  const [exporting, setExporting] = useState(false);

  const [importing, setImporting] = useState(false);
  const [importResult, setImportResult] = useState(null);
  const [importError, setImportError] = useState('');

  const handleExport = async () => {
    setExporting(true);
    try {
      const resp = await axios.get('/api/passwords');
      const entries = await Promise.all(resp.data.map(async (p) => decryptJson(userKey, p.encrypted_data, p.data_iv)));

      const payload = {
        windkeyExportVersion: 1,
        exportedAt: new Date().toISOString(),
        entries,
      };
      const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `windkey-export-${new Date().toISOString().slice(0, 10)}.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } finally {
      setExporting(false);
      setExportConfirmOpen(false);
      setExportAck(false);
    }
  };

  const handleFileChange = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setImportError('');
    setImportResult(null);
    setImporting(true);

    try {
      const text = await file.text();
      const parsed = JSON.parse(text);
      const entries = Array.isArray(parsed) ? parsed : Array.isArray(parsed.entries) ? parsed.entries : null;
      if (!entries) {
        throw new Error('Unbekanntes Dateiformat - erwarte ein Winkey-JSON-Export oder eine Liste von Einträgen');
      }

      let success = 0;
      let failed = 0;
      for (const entry of entries) {
        try {
          const { title, username, password, url, notes, totpSecret } = entry;
          if (!title || !password) { failed++; continue; }
          const { data, iv } = await encryptJson(userKey, { title, username: username || '', password, url: url || '', notes: notes || '', totpSecret: totpSecret || '' });
          await axios.post('/api/passwords', { encrypted_data: data, data_iv: iv });
          success++;
        } catch {
          failed++;
        }
      }
      setImportResult({ success, failed, total: entries.length });
      window.dispatchEvent(new Event('passwordsChanged'));
    } catch (err) {
      setImportError(err.message || 'Import fehlgeschlagen - ungültige Datei');
    } finally {
      setImporting(false);
      e.target.value = '';
    }
  };

  return (
    <Box>
      <Typography variant="h5" sx={{ mb: 3 }}>Import / Export</Typography>

      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" sx={{ mb: 1 }}>Exportieren</Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          Speichert alle deine Passwörter als entschlüsselte JSON-Datei auf deiner Festplatte - z.B. als Backup
          oder zum Umzug zu einem anderen Passwort-Manager.
        </Typography>
        <Alert severity="warning" sx={{ mb: 2 }}>
          Die exportierte Datei enthält alle Passwörter im <strong>Klartext</strong>, nicht verschlüsselt -
          das ist bei jedem Passwort-Manager-Export so (auch bei Bitwarden, 1Password, Chrome, ...), da die
          Datei ja auch von anderen Programmen lesbar sein soll. Lösche sie nach Gebrauch sicher und
          speichere sie nie an einem Ort, auf den andere Zugriff haben.
        </Alert>
        <Button
          variant="contained"
          startIcon={<DownloadIcon />}
          onClick={() => setExportConfirmOpen(true)}
          disabled={exporting}
        >
          Exportieren
        </Button>
      </Paper>

      <Paper sx={{ p: 3 }}>
        <Typography variant="h6" sx={{ mb: 1 }}>Importieren</Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          Lädt Einträge aus einer Winkey-JSON-Exportdatei (oder einer einfachen JSON-Liste mit
          title/username/password/url/notes-Feldern) und verschlüsselt sie beim Import wie gewohnt clientseitig.
        </Typography>
        <input type="file" accept="application/json" ref={fileInputRef} onChange={handleFileChange} style={{ display: 'none' }} />
        <Button
          variant="outlined"
          startIcon={<UploadIcon />}
          onClick={() => fileInputRef.current?.click()}
          disabled={importing}
        >
          Datei auswählen
        </Button>
        {importing && <LinearProgress sx={{ mt: 2 }} />}
        {importError && <Alert severity="error" sx={{ mt: 2 }}>{importError}</Alert>}
        {importResult && (
          <Alert severity={importResult.failed > 0 ? 'warning' : 'success'} sx={{ mt: 2 }}>
            {importResult.success} von {importResult.total} Einträgen importiert.
            {importResult.failed > 0 && ` ${importResult.failed} übersprungen (fehlender Titel/Passwort oder Fehler).`}
          </Alert>
        )}
      </Paper>

      <Dialog open={exportConfirmOpen} onClose={() => setExportConfirmOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Export bestätigen</DialogTitle>
        <DialogContent>
          <List dense>
            <ListItem>
              <ListItemIcon><DescriptionIcon /></ListItemIcon>
              <ListItemText primary="Die Datei enthält alle deine Passwörter im Klartext." />
            </ListItem>
          </List>
          <FormControlLabel
            sx={{ mt: 1 }}
            control={<Checkbox checked={exportAck} onChange={(e) => setExportAck(e.target.checked)} />}
            label="Ich verstehe, dass die exportierte Datei unverschlüsselt ist und werde sie sicher aufbewahren."
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setExportConfirmOpen(false)}>Abbrechen</Button>
          <Button onClick={handleExport} variant="contained" disabled={!exportAck || exporting}>
            Jetzt exportieren
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
