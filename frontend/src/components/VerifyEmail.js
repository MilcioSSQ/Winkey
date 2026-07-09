import React, { useEffect, useState } from 'react';
import { useNavigate, useSearchParams, Link as RouterLink } from 'react-router-dom';
import axios from 'axios';
import {
  Container, Paper, Typography, Box, Button, CircularProgress, Alert, Link as MuiLink,
  TextField,
} from '@mui/material';
import { MarkEmailRead as MarkEmailReadIcon } from '@mui/icons-material';

export default function VerifyEmail() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const token = searchParams.get('token');

  const [status, setStatus] = useState(token ? 'verifying' : 'no-token');
  const [error, setError] = useState('');
  const [resendEmail, setResendEmail] = useState('');
  const [resendSent, setResendSent] = useState(false);

  useEffect(() => {
    if (!token) return;
    axios.get(`https://${window.location.hostname}:5000/api/verify-email?token=${encodeURIComponent(token)}`)
      .then(() => setStatus('success'))
      .catch((err) => {
        setStatus('error');
        setError(err.response?.data?.error || 'Verifizierung fehlgeschlagen');
      });
  }, [token]);

  const handleResend = async (e) => {
    e.preventDefault();
    await axios.post(`https://${window.location.hostname}:5000/api/resend-verification`, { email: resendEmail });
    setResendSent(true);
  };

  return (
    <Box sx={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', p: 3 }}>
      <Container maxWidth="sm">
        <Paper sx={{ p: 4, borderRadius: 4, textAlign: 'center' }}>
          <MarkEmailReadIcon sx={{ fontSize: 48, color: 'primary.main', mb: 2 }} />

          {status === 'verifying' && (
            <>
              <Typography variant="h5" sx={{ mb: 2 }}>Bestätige E-Mail...</Typography>
              <CircularProgress />
            </>
          )}

          {status === 'success' && (
            <>
              <Typography variant="h5" sx={{ mb: 2 }}>E-Mail bestätigt!</Typography>
              <Typography color="text.secondary" sx={{ mb: 3 }}>
                Du kannst dich jetzt anmelden.
              </Typography>
              <Button variant="contained" onClick={() => navigate('/login')}>Zur Anmeldung</Button>
            </>
          )}

          {status === 'error' && (
            <>
              <Alert severity="error" sx={{ mb: 3, textAlign: 'left' }}>{error}</Alert>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Der Link ist abgelaufen oder ungültig. Neue Bestätigungs-E-Mail anfordern:
              </Typography>
              <Box component="form" onSubmit={handleResend} sx={{ display: 'flex', gap: 1 }}>
                <TextField
                  fullWidth size="small" label="E-Mail Adresse"
                  value={resendEmail} onChange={(e) => setResendEmail(e.target.value)}
                />
                <Button type="submit" variant="contained">Senden</Button>
              </Box>
              {resendSent && <Alert severity="info" sx={{ mt: 2 }}>Falls das Konto existiert, wurde eine neue E-Mail gesendet.</Alert>}
            </>
          )}

          {status === 'no-token' && (
            <Typography color="text.secondary">Kein Bestätigungs-Token in der URL gefunden.</Typography>
          )}

          <Box sx={{ mt: 3 }}>
            <MuiLink component={RouterLink} to="/login" variant="body2">Zurück zur Anmeldung</MuiLink>
          </Box>
        </Paper>
      </Container>
    </Box>
  );
}
