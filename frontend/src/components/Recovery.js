import React, { useState } from 'react';
import { useNavigate, Link as RouterLink } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import {
  Container, Paper, TextField, Button, Typography, Box, Alert, Link as MuiLink,
} from '@mui/material';
import { VpnKey as VpnKeyIcon } from '@mui/icons-material';

function checkPasswordRules(password) {
  return {
    length: password.length >= 8,
    uppercase: /[A-Z]/.test(password),
    lowercase: /[a-z]/.test(password),
    number: /[0-9]/.test(password),
    special: /[^A-Za-z0-9]/.test(password),
  };
}

export default function Recovery() {
  const navigate = useNavigate();
  const { recoverAccount } = useAuth();
  const [email, setEmail] = useState('');
  const [recoveryKey, setRecoveryKey] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const rulesPassed = Object.values(checkPasswordRules(newPassword)).every(Boolean);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (!rulesPassed) {
      setError('Das neue Master-Passwort erfüllt noch nicht alle Anforderungen (mind. 8 Zeichen, Groß-/Kleinbuchstabe, Zahl, Sonderzeichen)');
      return;
    }
    if (newPassword !== confirmPassword) {
      setError('Passwörter stimmen nicht überein');
      return;
    }

    setSubmitting(true);
    const result = await recoverAccount(email, recoveryKey.trim(), newPassword);
    setSubmitting(false);

    if (result.success) {
      setSuccess(true);
    } else {
      setError(result.error);
    }
  };

  if (success) {
    return (
      <Box sx={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', p: 3 }}>
        <Container maxWidth="sm">
          <Paper sx={{ p: 4, borderRadius: 4, textAlign: 'center' }}>
            <Typography variant="h5" sx={{ mb: 2 }}>Master-Passwort geändert</Typography>
            <Typography color="text.secondary" sx={{ mb: 3 }}>
              Du kannst dich jetzt mit deinem neuen Master-Passwort anmelden. Deine gespeicherten
              Passwörter sind unverändert - sie mussten nicht neu verschlüsselt werden.
            </Typography>
            <Button variant="contained" onClick={() => navigate('/login')}>Zur Anmeldung</Button>
          </Paper>
        </Container>
      </Box>
    );
  }

  return (
    <Box sx={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', p: 3 }}>
      <Container maxWidth="sm">
        <Paper sx={{ p: { xs: 3, sm: 4 }, borderRadius: 4 }}>
          <Box sx={{ mb: 3, textAlign: 'center' }}>
            <VpnKeyIcon sx={{ fontSize: 48, color: 'primary.main', mb: 2 }} />
            <Typography component="h1" variant="h4" sx={{ fontWeight: 700 }}>
              Master-Passwort zurücksetzen
            </Typography>
            <Typography color="text.secondary" sx={{ mt: 1 }}>
              Dafür brauchst du den Recovery Key, der dir bei der Registrierung einmalig angezeigt wurde.
            </Typography>
          </Box>

          {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
          <Alert severity="info" sx={{ mb: 3 }}>
            Ohne diesen Recovery Key ist eine Wiederherstellung nicht möglich - das ist eine bewusste
            Konsequenz der Zero-Knowledge-Verschlüsselung, nicht ein fehlendes Feature.
          </Alert>

          <Box component="form" onSubmit={handleSubmit}>
            <TextField
              margin="normal" required fullWidth label="E-Mail Adresse" autoFocus
              value={email} onChange={(e) => setEmail(e.target.value)} sx={{ mb: 2 }}
            />
            <TextField
              margin="normal" required fullWidth label="Recovery Key"
              placeholder="XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX"
              value={recoveryKey} onChange={(e) => setRecoveryKey(e.target.value)} sx={{ mb: 2 }}
            />
            <TextField
              margin="normal" required fullWidth label="Neues Master-Passwort" type="password"
              value={newPassword} onChange={(e) => setNewPassword(e.target.value)} sx={{ mb: 2 }}
            />
            <TextField
              margin="normal" required fullWidth label="Neues Master-Passwort bestätigen" type="password"
              value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} sx={{ mb: 3 }}
            />
            <Button type="submit" fullWidth variant="contained" disabled={submitting} sx={{ py: 1.5, mb: 2 }}>
              Master-Passwort ändern
            </Button>
          </Box>
          <Box sx={{ textAlign: 'center' }}>
            <MuiLink component={RouterLink} to="/login" variant="body2">Zurück zur Anmeldung</MuiLink>
          </Box>
        </Paper>
      </Container>
    </Box>
  );
}
