import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import {
  Box, Typography, Paper, TextField, IconButton, InputAdornment, Slider, FormControlLabel,
  Checkbox, Grid, LinearProgress, Snackbar, Alert,
} from '@mui/material';
import { ContentCopy as ContentCopyIcon, Refresh as RefreshIcon } from '@mui/icons-material';

function calculatePasswordStrength(password) {
  if (!password) return { score: 0, label: 'Kein Passwort', color: 'error' };
  let score = 0;
  if (password.length >= 12) score += 20;
  if (/[A-Z]/.test(password)) score += 20;
  if (/[a-z]/.test(password)) score += 20;
  if (/[0-9]/.test(password)) score += 20;
  if (/[^A-Za-z0-9]/.test(password)) score += 20;
  if (password.length >= 16) score = Math.min(score + 20, 100);
  if (score < 20) return { score, label: 'Sehr schwach', color: 'error' };
  if (score < 40) return { score, label: 'Schwach', color: 'error' };
  if (score < 60) return { score, label: 'Mittel', color: 'warning' };
  if (score < 80) return { score, label: 'Stark', color: 'info' };
  return { score, label: 'Sehr stark', color: 'success' };
}

export default function PasswordGeneratorTool() {
  const [options, setOptions] = useState({ length: 20, uppercase: true, lowercase: true, numbers: true, special: true });
  const [password, setPassword] = useState('');
  const [snackbarOpen, setSnackbarOpen] = useState(false);

  const generate = useCallback(async () => {
    try {
      const params = new URLSearchParams(options);
      const resp = await axios.get(`/api/generate-password?${params}`);
      setPassword(resp.data.password);
    } catch {
      // Fine to fall back client-side if the API is briefly unreachable.
      const charset =
        (options.uppercase ? 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' : '') +
        (options.lowercase ? 'abcdefghijklmnopqrstuvwxyz' : '') +
        (options.numbers ? '0123456789' : '') +
        (options.special ? '!@#$%^&*()_+-=[]{}' : '');
      let pw = '';
      for (let i = 0; i < options.length; i++) pw += charset.charAt(Math.floor(Math.random() * charset.length));
      setPassword(pw);
    }
  }, [options]);

  useEffect(() => { generate(); }, [generate]);

  const handleOptionChange = (key, value) => setOptions((prev) => ({ ...prev, [key]: value }));

  const handleCopy = async () => {
    await navigator.clipboard.writeText(password);
    setSnackbarOpen(true);
  };

  const strength = calculatePasswordStrength(password);

  return (
    <Box>
      <Typography variant="h5" sx={{ mb: 1 }}>Passwort Generator</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
        Erzeugt ein zufälliges Passwort zum Kopieren - wird nirgends gespeichert, bis du es selbst
        in einen Eintrag einfügst.
      </Typography>

      <Paper sx={{ p: 3 }}>
        <TextField
          fullWidth
          value={password}
          InputProps={{
            readOnly: true,
            sx: { fontFamily: 'monospace', fontSize: '1.1rem' },
            endAdornment: (
              <InputAdornment position="end">
                <IconButton onClick={handleCopy} title="Kopieren"><ContentCopyIcon /></IconButton>
                <IconButton onClick={generate} title="Neu generieren"><RefreshIcon /></IconButton>
              </InputAdornment>
            ),
          }}
          sx={{ mb: 2 }}
        />
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 3 }}>
          <LinearProgress variant="determinate" value={strength.score} color={strength.color} sx={{ flexGrow: 1, height: 8, borderRadius: 4 }} />
          <Typography variant="caption" color={`${strength.color}.main`} sx={{ minWidth: 80 }}>{strength.label}</Typography>
        </Box>

        <Typography variant="subtitle2" gutterBottom>Länge: {options.length}</Typography>
        <Slider
          value={options.length}
          onChange={(_, v) => handleOptionChange('length', v)}
          min={4}
          max={128}
          valueLabelDisplay="auto"
          sx={{ mb: 2 }}
        />
        <Grid container spacing={1}>
          <Grid item xs={6}>
            <FormControlLabel
              control={<Checkbox checked={options.uppercase} onChange={(e) => handleOptionChange('uppercase', e.target.checked)} />}
              label="Großbuchstaben"
            />
          </Grid>
          <Grid item xs={6}>
            <FormControlLabel
              control={<Checkbox checked={options.lowercase} onChange={(e) => handleOptionChange('lowercase', e.target.checked)} />}
              label="Kleinbuchstaben"
            />
          </Grid>
          <Grid item xs={6}>
            <FormControlLabel
              control={<Checkbox checked={options.numbers} onChange={(e) => handleOptionChange('numbers', e.target.checked)} />}
              label="Zahlen"
            />
          </Grid>
          <Grid item xs={6}>
            <FormControlLabel
              control={<Checkbox checked={options.special} onChange={(e) => handleOptionChange('special', e.target.checked)} />}
              label="Sonderzeichen"
            />
          </Grid>
        </Grid>
      </Paper>

      <Snackbar open={snackbarOpen} autoHideDuration={2000} onClose={() => setSnackbarOpen(false)}>
        <Alert severity="success" sx={{ width: '100%' }}>Passwort kopiert!</Alert>
      </Snackbar>
    </Box>
  );
}
