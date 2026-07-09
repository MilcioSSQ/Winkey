import React, { useState } from 'react';
import { useAuth } from '../contexts/AuthContext';
import {
  Container, Paper, TextField, Button, Typography, Box, InputAdornment, IconButton, Alert,
} from '@mui/material';
import {
  Lock as LockIcon, Visibility as VisibilityIcon, VisibilityOff as VisibilityOffIcon,
} from '@mui/icons-material';

export default function Unlock() {
  const { unlock, logout, user } = useAuth();
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSubmitting(true);
    const result = await unlock(password);
    setSubmitting(false);
    if (!result.success) {
      setError(result.error);
    }
  };

  return (
    <Box sx={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', p: 3 }}>
      <Container maxWidth="sm">
        <Paper elevation={1} sx={{ p: { xs: 3, sm: 4 }, borderRadius: 4 }}>
          <Box sx={{ mb: 3, textAlign: 'center' }}>
            <LockIcon sx={{ fontSize: 48, color: 'primary.main', mb: 2 }} />
            <Typography component="h1" variant="h4" sx={{ fontWeight: 700, mb: 1 }}>
              Tresor gesperrt
            </Typography>
            <Typography variant="body1" color="text.secondary">
              Angemeldet als {user?.email}. Gib dein Master-Passwort ein, um den Tresor zu entsperren.
            </Typography>
          </Box>

          {error && <Alert severity="error" sx={{ mb: 3 }}>{error}</Alert>}

          <Box component="form" onSubmit={handleSubmit}>
            <TextField
              margin="normal"
              required
              fullWidth
              autoFocus
              label="Master-Passwort"
              type={showPassword ? 'text' : 'password'}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              InputProps={{
                endAdornment: (
                  <InputAdornment position="end">
                    <IconButton onClick={() => setShowPassword(!showPassword)} edge="end">
                      {showPassword ? <VisibilityOffIcon /> : <VisibilityIcon />}
                    </IconButton>
                  </InputAdornment>
                ),
              }}
              sx={{ mb: 3 }}
            />
            <Button type="submit" fullWidth variant="contained" disabled={submitting} sx={{ py: 1.5, mb: 2 }}>
              Entsperren
            </Button>
            <Button fullWidth variant="text" onClick={logout}>
              Abmelden
            </Button>
          </Box>
        </Paper>
      </Container>
    </Box>
  );
}
