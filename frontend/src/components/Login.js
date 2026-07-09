import React, { useState } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { Link as RouterLink } from 'react-router-dom';
import {
  Container,
  Paper,
  TextField,
  Button,
  Typography,
  Box,
  Link as MuiLink,
  InputAdornment,
  IconButton,
  Alert,
  FormControlLabel,
  Checkbox,
} from '@mui/material';
import {
  Security as SecurityIcon,
  Mail as MailIcon,
  Lock as LockIcon,
  Key as KeyIcon,
  Visibility as VisibilityIcon,
  VisibilityOff as VisibilityOffIcon,
} from '@mui/icons-material';

export default function Login() {
  const { login, verifyTwoFactor } = useAuth();
  const [step, setStep] = useState('password'); // 'password' | 'twofa'
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [rememberMe, setRememberMe] = useState(false);
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const handlePasswordSubmit = async (e) => {
    e.preventDefault();
    setError('');
    if (!email || !password) {
      setError('E-Mail und Passwort sind erforderlich');
      return;
    }
    setSubmitting(true);
    const result = await login(email, password, rememberMe);
    setSubmitting(false);
    if (result.success) {
      setStep('twofa');
    } else {
      setError(result.error);
    }
  };

  const handleTwoFaSubmit = async (e) => {
    e.preventDefault();
    setError('');
    if (!code) {
      setError('2FA-Code ist erforderlich');
      return;
    }
    setSubmitting(true);
    const result = await verifyTwoFactor(code);
    setSubmitting(false);
    if (!result.success) {
      setError(result.error);
    }
  };

  return (
    <Box
      sx={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        backgroundColor: 'background.default',
        p: 3,
      }}
    >
      <Container maxWidth="sm">
        <Paper elevation={1} sx={{ p: { xs: 3, sm: 4 }, borderRadius: 4 }}>
          <Box sx={{ mb: 4, textAlign: 'center' }}>
            <SecurityIcon sx={{ fontSize: 48, color: 'primary.main', mb: 2 }} />
            <Typography component="h1" variant="h4" sx={{ fontWeight: 700, mb: 1 }}>
              Willkommen zurück
            </Typography>
            <Typography variant="body1" sx={{ color: 'text.secondary' }}>
              {step === 'password'
                ? 'Melde dich mit deinem Master-Passwort an'
                : 'Gib den Code aus deiner Authenticator-App ein'}
            </Typography>
          </Box>

          {error && <Alert severity="error" sx={{ mb: 3 }}>{error}</Alert>}

          {step === 'password' ? (
            <Box component="form" onSubmit={handlePasswordSubmit}>
              <TextField
                margin="normal"
                required
                fullWidth
                label="E-Mail Adresse"
                autoComplete="email"
                autoFocus
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start"><MailIcon color="action" /></InputAdornment>
                  ),
                }}
                sx={{ mb: 2 }}
              />
              <TextField
                margin="normal"
                required
                fullWidth
                label="Master-Passwort"
                type={showPassword ? 'text' : 'password'}
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start"><LockIcon color="action" /></InputAdornment>
                  ),
                  endAdornment: (
                    <InputAdornment position="end">
                      <IconButton onClick={() => setShowPassword(!showPassword)} edge="end">
                        {showPassword ? <VisibilityOffIcon /> : <VisibilityIcon />}
                      </IconButton>
                    </InputAdornment>
                  ),
                }}
                sx={{ mb: 1 }}
              />
              <FormControlLabel
                control={<Checkbox checked={rememberMe} onChange={(e) => setRememberMe(e.target.checked)} />}
                label="Angemeldet bleiben (30 Tage)"
                sx={{ mb: 2 }}
              />
              <Button type="submit" fullWidth variant="contained" disabled={submitting} sx={{ py: 1.5, mb: 2 }}>
                Weiter
              </Button>
            </Box>
          ) : (
            <Box component="form" onSubmit={handleTwoFaSubmit}>
              <TextField
                margin="normal"
                required
                fullWidth
                label="2FA Code"
                autoFocus
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/[^0-9]/g, '').slice(0, 6))}
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start"><KeyIcon color="action" /></InputAdornment>
                  ),
                }}
                sx={{ mb: 3 }}
              />
              <Button type="submit" fullWidth variant="contained" disabled={submitting} sx={{ py: 1.5, mb: 2 }}>
                Anmelden
              </Button>
            </Box>
          )}

          <Box sx={{ textAlign: 'center', mt: 1 }}>
            <MuiLink component={RouterLink} to="/recovery" variant="body2" sx={{ display: 'block', mb: 1 }}>
              Master-Passwort vergessen?
            </MuiLink>
            <MuiLink component={RouterLink} to="/register" variant="body2">
              Noch kein Konto? Jetzt registrieren
            </MuiLink>
          </Box>
        </Paper>
      </Container>
    </Box>
  );
}
