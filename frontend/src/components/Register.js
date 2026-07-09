import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import {
  Container,
  Paper,
  TextField,
  Button,
  Typography,
  Box,
  Link as MuiLink,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  InputAdornment,
  IconButton,
  Alert,
  FormControlLabel,
  Checkbox,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
} from '@mui/material';
import {
  Security as SecurityIcon,
  Mail as MailIcon,
  Lock as LockIcon,
  Visibility as VisibilityIcon,
  VisibilityOff as VisibilityOffIcon,
  QrCode2 as QrCode2Icon,
  CheckCircle as CheckCircleIcon,
  RadioButtonUnchecked as RadioButtonUncheckedIcon,
  VpnKey as VpnKeyIcon,
  ContentCopy as ContentCopyIcon,
} from '@mui/icons-material';
import { Link as RouterLink } from 'react-router-dom';

function checkPasswordRules(password) {
  return {
    length: password.length >= 8,
    uppercase: /[A-Z]/.test(password),
    lowercase: /[a-z]/.test(password),
    number: /[0-9]/.test(password),
    special: /[^A-Za-z0-9]/.test(password),
  };
}

const RULE_LABELS = {
  length: 'Mindestens 8 Zeichen',
  uppercase: 'Mindestens 1 Großbuchstabe',
  lowercase: 'Mindestens 1 Kleinbuchstabe',
  number: 'Mindestens 1 Zahl',
  special: 'Mindestens 1 Sonderzeichen',
};

export default function Register() {
  const navigate = useNavigate();
  const { register } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const [twoFactorSecret, setTwoFactorSecret] = useState('');
  const [qrCode, setQrCode] = useState('');
  const [recoveryKey, setRecoveryKey] = useState('');
  const [emailSent, setEmailSent] = useState(true);
  const [showTwoFactorDialog, setShowTwoFactorDialog] = useState(false);
  const [recoveryKeySaved, setRecoveryKeySaved] = useState(false);

  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);

  const rules = checkPasswordRules(password);
  const rulesPassed = Object.values(rules).every(Boolean);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (!rulesPassed) {
      setError('Das Master-Passwort erfüllt noch nicht alle Anforderungen');
      return;
    }
    if (password !== confirmPassword) {
      setError('Passwörter stimmen nicht überein');
      return;
    }

    setSubmitting(true);
    const result = await register(email, password);
    setSubmitting(false);

    if (result.success) {
      setTwoFactorSecret(result.twoFactorSecret);
      setQrCode(result.qrCode);
      setRecoveryKey(result.recoveryKeyFormatted);
      setEmailSent(result.emailSent);
      setShowTwoFactorDialog(true);
    } else {
      setError(result.error);
    }
  };

  const handleDialogClose = () => {
    setShowTwoFactorDialog(false);
    navigate('/login');
  };

  return (
    <Box sx={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', bgcolor: 'background.default' }}>
      <Container maxWidth="sm">
        <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
          <Paper elevation={3} sx={{ p: { xs: 3, sm: 5 }, width: '100%', borderRadius: 4, border: '1px solid', borderColor: 'divider' }}>
            <Box sx={{ mb: 4, textAlign: 'center' }}>
              <SecurityIcon sx={{ fontSize: 48, color: 'primary.main', mb: 2 }} />
              <Typography component="h1" variant="h4" sx={{ fontWeight: 700 }}>
                Konto erstellen
              </Typography>
              <Typography variant="body1" sx={{ mt: 1, color: 'text.secondary' }}>
                Dein Master-Passwort verlässt niemals deinen Browser - der Server sieht es nie.
              </Typography>
            </Box>

            {error && (
              <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>
            )}

            <Box component="form" onSubmit={handleSubmit}>
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
                  startAdornment: <InputAdornment position="start"><MailIcon color="action" /></InputAdornment>,
                }}
                sx={{ mb: 2 }}
              />
              <TextField
                margin="normal"
                required
                fullWidth
                label="Master-Passwort"
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                InputProps={{
                  startAdornment: <InputAdornment position="start"><LockIcon color="action" /></InputAdornment>,
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

              {password && (
                <List dense sx={{ mb: 1, py: 0 }}>
                  {Object.entries(rules).map(([key, passed]) => (
                    <ListItem key={key} sx={{ py: 0 }}>
                      <ListItemIcon sx={{ minWidth: 32 }}>
                        {passed
                          ? <CheckCircleIcon fontSize="small" color="success" />
                          : <RadioButtonUncheckedIcon fontSize="small" color="disabled" />}
                      </ListItemIcon>
                      <ListItemText
                        primary={RULE_LABELS[key]}
                        primaryTypographyProps={{ variant: 'caption', color: passed ? 'success.main' : 'text.secondary' }}
                      />
                    </ListItem>
                  ))}
                </List>
              )}

              <TextField
                margin="normal"
                required
                fullWidth
                label="Master-Passwort bestätigen"
                type={showConfirmPassword ? 'text' : 'password'}
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                InputProps={{
                  startAdornment: <InputAdornment position="start"><LockIcon color="action" /></InputAdornment>,
                  endAdornment: (
                    <InputAdornment position="end">
                      <IconButton onClick={() => setShowConfirmPassword(!showConfirmPassword)} edge="end">
                        {showConfirmPassword ? <VisibilityOffIcon /> : <VisibilityIcon />}
                      </IconButton>
                    </InputAdornment>
                  ),
                }}
                sx={{ mb: 3 }}
              />

              <Alert severity="warning" sx={{ mb: 3 }}>
                Es gibt zero-knowledge-bedingt kein normales "Passwort vergessen per E-Mail". Nur dein
                Recovery Key (im nächsten Schritt) kann dein Master-Passwort später zurücksetzen. Verlierst
                du beides, sind deine gespeicherten Passwörter unwiederbringlich verloren.
              </Alert>

              <Button type="submit" fullWidth variant="contained" disabled={submitting} sx={{ py: 1.5, borderRadius: 2 }}>
                Registrieren
              </Button>
              <Box sx={{ mt: 3, textAlign: 'center' }}>
                <Typography variant="body2" color="text.secondary">
                  Bereits ein Konto?{' '}
                  <MuiLink component={RouterLink} to="/login">Anmelden</MuiLink>
                </Typography>
              </Box>
            </Box>
          </Paper>
        </Box>
      </Container>

      <Dialog open={showTwoFactorDialog} onClose={() => {}} maxWidth="sm" fullWidth disableEscapeKeyDown>
        <DialogTitle>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <QrCode2Icon color="primary" />
            <Typography variant="h6">Zwei-Faktor-Authentifizierung</Typography>
          </Box>
        </DialogTitle>
        <DialogContent>
          <Typography variant="body1" paragraph>
            Scanne den QR-Code mit Google Authenticator (oder einer kompatiblen App):
          </Typography>
          <Box sx={{ display: 'flex', justifyContent: 'center', my: 2 }}>
            {qrCode && <img src={qrCode} alt="2FA QR Code" style={{ maxWidth: '200px', height: 'auto' }} />}
          </Box>
          <Typography variant="body2" color="text.secondary">
            Alternativ manuell eingeben:
          </Typography>
          <Typography variant="body1" sx={{ fontFamily: 'monospace', bgcolor: 'background.default', p: 2, borderRadius: 1, mt: 1, wordBreak: 'break-all' }}>
            {twoFactorSecret}
          </Typography>

          <Box sx={{ mt: 3, mb: 1, display: 'flex', alignItems: 'center', gap: 1 }}>
            <VpnKeyIcon color="warning" />
            <Typography variant="h6">Dein Recovery Key</Typography>
          </Box>
          <Alert severity="error" sx={{ mb: 2 }}>
            Dieser Code wird nur EIN EINZIGES MAL angezeigt. Speichere ihn jetzt an einem sicheren Ort
            (Passwort-Manager eines Familienmitglieds, ausgedrucktes Papier im Safe, o.ä.). Ohne ihn kann
            dein Master-Passwort später nicht zurückgesetzt werden.
          </Alert>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, bgcolor: 'background.default', p: 2, borderRadius: 1 }}>
            <Typography variant="body1" sx={{ fontFamily: 'monospace', fontWeight: 600, flexGrow: 1, wordBreak: 'break-all' }}>
              {recoveryKey}
            </Typography>
            <IconButton onClick={() => navigator.clipboard.writeText(recoveryKey)} title="Kopieren">
              <ContentCopyIcon />
            </IconButton>
          </Box>

          {!emailSent && (
            <Alert severity="info" sx={{ mt: 3 }}>
              Es konnte keine Bestätigungs-E-Mail gesendet werden (SMTP nicht konfiguriert). Bitte
              MAIL_USERNAME/MAIL_PASSWORD in backend/.env setzen, oder wende dich an den Administrator.
            </Alert>
          )}
          {emailSent && (
            <Alert severity="info" sx={{ mt: 3 }}>
              Eine Bestätigungs-E-Mail wurde gesendet. Du musst deine E-Mail-Adresse bestätigen, bevor du
              dich anmelden kannst.
            </Alert>
          )}

          <FormControlLabel
            sx={{ mt: 2 }}
            control={<Checkbox checked={recoveryKeySaved} onChange={(e) => setRecoveryKeySaved(e.target.checked)} />}
            label="Ich habe den Recovery Key sicher gespeichert"
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={handleDialogClose} variant="contained" disabled={!recoveryKeySaved}>
            Weiter zur Anmeldung
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
