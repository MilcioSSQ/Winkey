import React, { useState } from 'react';
import axios from 'axios';
import {
  Box, Typography, Paper, TextField, Button, Alert, List, ListItem, ListItemIcon, ListItemText,
  Divider, Chip, CircularProgress, InputAdornment, IconButton,
} from '@mui/material';
import {
  Mail as MailIcon, Lock as LockIcon, Visibility as VisibilityIcon, VisibilityOff as VisibilityOffIcon,
  Warning as WarningIcon, CheckCircle as CheckCircleIcon, ErrorOutline as ErrorOutlineIcon,
} from '@mui/icons-material';
import { sha1Hex } from '../crypto/windkeyCrypto';

export default function BreachScanner() {
  const [email, setEmail] = useState('');
  const [emailChecking, setEmailChecking] = useState(false);
  const [emailResult, setEmailResult] = useState(null);
  const [emailError, setEmailError] = useState('');
  const [emailNotConfigured, setEmailNotConfigured] = useState(false);

  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [passwordChecking, setPasswordChecking] = useState(false);
  const [passwordResult, setPasswordResult] = useState(null);
  const [passwordError, setPasswordError] = useState('');

  const checkEmail = async () => {
    setEmailChecking(true);
    setEmailError('');
    setEmailResult(null);
    setEmailNotConfigured(false);
    try {
      const resp = await axios.post('/api/check-email-breach', { email });
      setEmailResult(resp.data);
    } catch (err) {
      if (err.response?.status === 501) {
        setEmailNotConfigured(true);
      } else {
        setEmailError(err.response?.data?.error || 'Prüfung fehlgeschlagen');
      }
    } finally {
      setEmailChecking(false);
    }
  };

  const checkPassword = async () => {
    setPasswordChecking(true);
    setPasswordError('');
    setPasswordResult(null);
    try {
      const fullHash = await sha1Hex(password);
      const prefix = fullHash.slice(0, 5);
      const suffix = fullHash.slice(5);
      const resp = await axios.post('/api/check-password-breach', { sha1Prefix: prefix });
      const match = resp.data.suffixes.find((s) => s.suffix === suffix);
      setPasswordResult(match ? { breached: true, count: match.count } : { breached: false });
    } catch (err) {
      setPasswordError(err.response?.data?.error || 'Prüfung fehlgeschlagen');
    } finally {
      setPasswordChecking(false);
    }
  };

  return (
    <Box>
      <Typography variant="h5" sx={{ mb: 1 }}>Datenleck Scanner</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
        Prüft eine E-Mail-Adresse oder ein Passwort direkt gegen HaveIBeenPwned - unabhängig von
        deinen gespeicherten Einträgen.
      </Typography>

      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" sx={{ mb: 1 }}>E-Mail-Adresse prüfen</Typography>
        <Alert severity="info" sx={{ mb: 2 }}>
          Die eingegebene E-Mail-Adresse wird an HaveIBeenPwned gesendet - das ist bei dieser Art
          von Prüfung unvermeidbar (anders als beim Passwort-Check unten).
        </Alert>
        <Box sx={{ display: 'flex', gap: 1, mb: 2 }}>
          <TextField
            fullWidth
            size="small"
            label="E-Mail-Adresse"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            InputProps={{ startAdornment: <InputAdornment position="start"><MailIcon fontSize="small" /></InputAdornment> }}
          />
          <Button variant="contained" onClick={checkEmail} disabled={!email || emailChecking} sx={{ minWidth: 100 }}>
            {emailChecking ? <CircularProgress size={20} color="inherit" /> : 'Prüfen'}
          </Button>
        </Box>

        {emailNotConfigured && (
          <Alert severity="warning">
            Für die E-Mail-Prüfung ist ein kostenpflichtiger HaveIBeenPwned-API-Key nötig (~3,50$/Monat),
            der noch nicht konfiguriert ist. Einen Key gibt es unter{' '}
            <a href="https://haveibeenpwned.com/api/key" target="_blank" rel="noreferrer">haveibeenpwned.com/api/key</a>,
            dann in <code>backend/.env</code> als <code>HIBP_API_KEY</code> eintragen.
          </Alert>
        )}
        {emailError && <Alert severity="error">{emailError}</Alert>}
        {emailResult && !emailResult.breached && (
          <Alert severity="success" icon={<CheckCircleIcon />}>
            Keine bekannten Datenlecks für diese E-Mail-Adresse gefunden.
          </Alert>
        )}
        {emailResult?.breached && (
          <Box>
            <Alert severity="error" icon={<WarningIcon />} sx={{ mb: 2 }}>
              In {emailResult.breaches.length} Datenleck(s) gefunden!
            </Alert>
            <List dense>
              {emailResult.breaches.map((b) => (
                <React.Fragment key={b.name}>
                  <ListItem alignItems="flex-start">
                    <ListItemIcon><ErrorOutlineIcon color="error" /></ListItemIcon>
                    <ListItemText
                      primary={b.title}
                      secondary={
                        <>
                          {b.breachDate} —{' '}
                          {b.dataClasses.map((dc) => (
                            <Chip key={dc} label={dc} size="small" sx={{ mr: 0.5, mt: 0.5 }} />
                          ))}
                        </>
                      }
                    />
                  </ListItem>
                  <Divider component="li" />
                </React.Fragment>
              ))}
            </List>
          </Box>
        )}
      </Paper>

      <Paper sx={{ p: 3 }}>
        <Typography variant="h6" sx={{ mb: 1 }}>Passwort prüfen</Typography>
        <Alert severity="info" sx={{ mb: 2 }}>
          Das Passwort verlässt niemals deinen Browser - es wird lokal gehasht und nur ein
          5-stelliges Kürzel des Hashes an HaveIBeenPwned gesendet (k-Anonymität), genau wie bei
          haveibeenpwned.com selbst. Kein API-Key nötig, kostenlos.
        </Alert>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <TextField
            fullWidth
            size="small"
            label="Passwort"
            type={showPassword ? 'text' : 'password'}
            autoComplete="off"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            InputProps={{
              startAdornment: <InputAdornment position="start"><LockIcon fontSize="small" /></InputAdornment>,
              endAdornment: (
                <InputAdornment position="end">
                  <IconButton size="small" onClick={() => setShowPassword(!showPassword)}>
                    {showPassword ? <VisibilityOffIcon fontSize="small" /> : <VisibilityIcon fontSize="small" />}
                  </IconButton>
                </InputAdornment>
              ),
            }}
          />
          <Button variant="contained" onClick={checkPassword} disabled={!password || passwordChecking} sx={{ minWidth: 100 }}>
            {passwordChecking ? <CircularProgress size={20} color="inherit" /> : 'Prüfen'}
          </Button>
        </Box>

        {passwordError && <Alert severity="error" sx={{ mt: 2 }}>{passwordError}</Alert>}
        {passwordResult && !passwordResult.breached && (
          <Alert severity="success" icon={<CheckCircleIcon />} sx={{ mt: 2 }}>
            Dieses Passwort wurde in keinem bekannten Datenleck gefunden.
          </Alert>
        )}
        {passwordResult?.breached && (
          <Alert severity="error" icon={<WarningIcon />} sx={{ mt: 2 }}>
            Dieses Passwort wurde in {passwordResult.count.toLocaleString('de-DE')} Datenlecks gefunden -
            nicht mehr verwenden!
          </Alert>
        )}
      </Paper>
    </Box>
  );
}
