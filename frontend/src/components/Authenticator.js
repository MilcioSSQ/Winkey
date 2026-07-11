import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import {
  Box, Typography, Paper, Grid, Card, CardContent, LinearProgress, IconButton, Tooltip, Alert, CircularProgress,
} from '@mui/material';
import { ContentCopy as ContentCopyIcon, VerifiedUser as VerifiedUserIcon } from '@mui/icons-material';
import { useAuth } from '../contexts/AuthContext';
import { decryptJson, computeTotp, totpSecondsRemaining } from '../crypto/windkeyCrypto';

const TOTP_STEP = 30;

export default function Authenticator() {
  const { userKey } = useAuth();
  const [entries, setEntries] = useState([]); // { id, title, username, totpSecret }
  const [codes, setCodes] = useState({}); // id -> 6-digit code
  const [secondsLeft, setSecondsLeft] = useState(totpSecondsRemaining(TOTP_STEP));
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [copiedId, setCopiedId] = useState(null);

  const fetchEntries = useCallback(async () => {
    try {
      const resp = await axios.get('/api/passwords');
      const decrypted = await Promise.all(resp.data.map(async (p) => {
        const entry = await decryptJson(userKey, p.encrypted_data, p.data_iv);
        return { id: p.id, title: entry.title, username: entry.username, totpSecret: entry.totpSecret };
      }));
      setEntries(decrypted.filter((e) => e.totpSecret));
      setLoading(false);
    } catch (err) {
      setError('Fehler beim Laden der Einträge');
      setLoading(false);
    }
  }, [userKey]);

  useEffect(() => {
    if (userKey) fetchEntries();
  }, [userKey, fetchEntries]);

  const refreshCodes = useCallback(async () => {
    const next = {};
    for (const entry of entries) {
      try {
        next[entry.id] = await computeTotp(entry.totpSecret);
      } catch {
        next[entry.id] = 'ungültig';
      }
    }
    setCodes(next);
  }, [entries]);

  useEffect(() => {
    refreshCodes();
    const interval = setInterval(() => {
      const remaining = totpSecondsRemaining(TOTP_STEP);
      setSecondsLeft(remaining);
      if (remaining === TOTP_STEP) refreshCodes();
    }, 1000);
    return () => clearInterval(interval);
  }, [refreshCodes]);

  const handleCopy = (id, code) => {
    navigator.clipboard.writeText(code);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1500);
  };

  if (loading) {
    return <Box sx={{ display: 'flex', justifyContent: 'center', pt: 4 }}><CircularProgress /></Box>;
  }
  if (error) {
    return <Alert severity="error">{error}</Alert>;
  }

  return (
    <Box>
      <Typography variant="h5" sx={{ mb: 1 }}>Authentifikator</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
        2FA-Codes für andere Dienste, deren Secret du bei einem Passwort-Eintrag hinterlegt hast
        (Feld "2FA Secret dieses Dienstes"). Nicht zu verwechseln mit deinem eigenen Winkey-Login-2FA.
      </Typography>

      {entries.length === 0 ? (
        <Paper sx={{ p: 4, textAlign: 'center' }}>
          <VerifiedUserIcon sx={{ fontSize: 40, color: 'text.secondary', mb: 1 }} />
          <Typography color="text.secondary">
            Noch keine Einträge mit einem 2FA-Secret. Füge beim Bearbeiten eines Passwort-Eintrags
            ein "2FA Secret dieses Dienstes" hinzu, um es hier zu sehen.
          </Typography>
        </Paper>
      ) : (
        <Grid container spacing={3}>
          {entries.map((entry) => (
            <Grid item xs={12} sm={6} md={4} key={entry.id}>
              <Card sx={{ height: '100%' }}>
                <CardContent>
                  <Typography variant="h6" sx={{ mb: 0.5 }}>{entry.title}</Typography>
                  {entry.username && (
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>{entry.username}</Typography>
                  )}
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                    <Typography variant="h4" sx={{ fontFamily: 'monospace', letterSpacing: 4 }}>
                      {codes[entry.id] ? codes[entry.id].match(/.{1,3}/g)?.join(' ') : '------'}
                    </Typography>
                    <Tooltip title={copiedId === entry.id ? 'Kopiert!' : 'Kopieren'}>
                      <IconButton size="small" onClick={() => handleCopy(entry.id, codes[entry.id])}>
                        <ContentCopyIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                  </Box>
                  <LinearProgress
                    variant="determinate"
                    value={(secondsLeft / TOTP_STEP) * 100}
                    color={secondsLeft <= 5 ? 'error' : 'primary'}
                    sx={{ height: 6, borderRadius: 3 }}
                  />
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      )}
    </Box>
  );
}
