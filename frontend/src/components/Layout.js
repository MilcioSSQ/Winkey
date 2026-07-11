import React, { useState, useEffect } from 'react';
import { Link, useLocation, Outlet } from 'react-router-dom';
import {
  AppBar,
  Box,
  Toolbar,
  Typography,
  Button,
  IconButton,
  Container,
  Menu,
  MenuItem,
  useTheme as useMuiTheme,
  alpha,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  FormControl,
  InputLabel,
  OutlinedInput,
  InputAdornment,
  FormHelperText,
  LinearProgress,
  Tooltip,
  Slider,
  FormControlLabel,
  Checkbox,
  Alert,
  Select,
  Drawer,
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  useMediaQuery,
} from '@mui/material';
import {
  Menu as MenuIcon,
  Folder as FolderIcon,
  Assessment as AssessmentIcon,
  Add as AddIcon,
  AccountCircle,
  Brightness4,
  Brightness7,
  Visibility,
  VisibilityOff,
  Refresh as RefreshIcon,
  ContentCopy as ContentCopyIcon,
  History as HistoryIcon,
  Security as SecurityIcon,
} from '@mui/icons-material';
import { useAuth } from '../contexts/AuthContext';
import { useTheme } from '../contexts/ThemeContext';
import { encryptJson, decryptJson } from '../crypto/windkeyCrypto';
import axios from 'axios';

export default function Layout() {
  const location = useLocation();
  const { logout, user, userKey } = useAuth();
  const { darkMode, toggleDarkMode } = useTheme();
  const muiTheme = useMuiTheme();
  const isMobile = useMediaQuery(muiTheme.breakpoints.down('sm'));
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [anchorEl, setAnchorEl] = useState(null);
  const [openNewPasswordDialog, setOpenNewPasswordDialog] = useState(false);
  const [categories, setCategories] = useState([]);
  const [newPassword, setNewPassword] = useState({
    title: '',
    username: '',
    password: '',
    url: '',
    notes: '',
    category_id: ''
  });
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [passwordStrength, setPasswordStrength] = useState({ score: 0, label: 'Kein Passwort', color: 'error' });
  const [generatorSettings, setGeneratorSettings] = useState({
    length: 16,
    uppercase: true,
    lowercase: true,
    numbers: true,
    special: true,
  });
  const [showCopiedMessage, setShowCopiedMessage] = useState(false);

  useEffect(() => {
    if (userKey) {
      fetchCategories();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [userKey]);

  useEffect(() => {
    // See Dashboard.js for why: best-effort re-masking, not real screenshot protection.
    const hide = () => setShowPassword(false);
    const handleVisibilityChange = () => { if (document.hidden) hide(); };
    document.addEventListener('visibilitychange', handleVisibilityChange);
    window.addEventListener('blur', hide);
    return () => {
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      window.removeEventListener('blur', hide);
    };
  }, []);

  const fetchCategories = async () => {
    try {
      const response = await axios.get('/api/categories');
      const decrypted = await Promise.all(response.data.map(async (c) => {
        const { name } = await decryptJson(userKey, c.encrypted_name, c.name_iv);
        return { ...c, name };
      }));
      setCategories(decrypted);
    } catch (error) {
      console.error('Failed to fetch categories:', error);
    }
  };

  const calculatePasswordStrength = (password) => {
    if (!password) return { score: 0, label: 'Kein Passwort', color: 'error' };
    
    let score = 0;
    const checks = {
      length: password.length >= 12,
      uppercase: /[A-Z]/.test(password),
      lowercase: /[a-z]/.test(password),
      numbers: /[0-9]/.test(password),
      special: /[^A-Za-z0-9]/.test(password),
      length_bonus: password.length >= 16
    };
    
    if (checks.length) score += 20;
    if (checks.uppercase) score += 20;
    if (checks.lowercase) score += 20;
    if (checks.numbers) score += 20;
    if (checks.special) score += 20;
    if (checks.length_bonus) score += 20;
    
    score = Math.min(score, 100);
    
    if (score < 20) return { score, label: 'Sehr schwach', color: 'error' };
    if (score < 40) return { score, label: 'Schwach', color: 'error' };
    if (score < 60) return { score, label: 'Mittel', color: 'warning' };
    if (score < 80) return { score, label: 'Stark', color: 'info' };
    return { score, label: 'Sehr stark', color: 'success' };
  };

  const generatePassword = () => {
    const charset = {
      uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
      lowercase: 'abcdefghijklmnopqrstuvwxyz',
      numbers: '0123456789',
      special: '!@#$%^&*()_+-=[]{}|;:,.<>?'
    };

    let availableChars = '';
    if (generatorSettings.uppercase) availableChars += charset.uppercase;
    if (generatorSettings.lowercase) availableChars += charset.lowercase;
    if (generatorSettings.numbers) availableChars += charset.numbers;
    if (generatorSettings.special) availableChars += charset.special;

    if (!availableChars) {
      setError('Please select at least one character type');
      return;
    }

    let password = '';
    for (let i = 0; i < generatorSettings.length; i++) {
      const randomIndex = Math.floor(Math.random() * availableChars.length);
      password += availableChars[randomIndex];
    }

    // Ensure at least one character of each selected type is included
    let finalPassword = password;
    if (generatorSettings.uppercase && !/[A-Z]/.test(password)) {
      const randomChar = charset.uppercase[Math.floor(Math.random() * charset.uppercase.length)];
      const randomPos = Math.floor(Math.random() * password.length);
      finalPassword = finalPassword.substring(0, randomPos) + randomChar + finalPassword.substring(randomPos + 1);
    }
    if (generatorSettings.lowercase && !/[a-z]/.test(password)) {
      const randomChar = charset.lowercase[Math.floor(Math.random() * charset.lowercase.length)];
      const randomPos = Math.floor(Math.random() * password.length);
      finalPassword = finalPassword.substring(0, randomPos) + randomChar + finalPassword.substring(randomPos + 1);
    }
    if (generatorSettings.numbers && !/[0-9]/.test(password)) {
      const randomChar = charset.numbers[Math.floor(Math.random() * charset.numbers.length)];
      const randomPos = Math.floor(Math.random() * password.length);
      finalPassword = finalPassword.substring(0, randomPos) + randomChar + finalPassword.substring(randomPos + 1);
    }
    if (generatorSettings.special && !/[^A-Za-z0-9]/.test(password)) {
      const randomChar = charset.special[Math.floor(Math.random() * charset.special.length)];
      const randomPos = Math.floor(Math.random() * password.length);
      finalPassword = finalPassword.substring(0, randomPos) + randomChar + finalPassword.substring(randomPos + 1);
    }

    setNewPassword(prev => ({ ...prev, password: finalPassword }));
    setPasswordStrength(calculatePasswordStrength(finalPassword));
  };

  const handleMenu = (event) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  const handleLogout = async () => {
    try {
      await logout();
      handleClose();
    } catch (error) {
      console.error('Failed to log out', error);
    }
  };

  const handleNewPasswordClick = () => {
    setOpenNewPasswordDialog(true);
    fetchCategories(); // Fetch latest categories when opening dialog
  };

  const handleNewPasswordClose = () => {
    setOpenNewPasswordDialog(false);
    setNewPassword({
      title: '',
      username: '',
      password: '',
      url: '',
      notes: '',
      category_id: ''
    });
    setError('');
    setPasswordStrength({ score: 0, label: 'Kein Passwort', color: 'error' });
  };

  const handleNewPasswordSubmit = async () => {
    try {
      if (!newPassword.title || !newPassword.password) {
        setError('Title and password are required');
        return;
      }

      const { title, username, password, url, notes, category_id } = newPassword;
      const { data, iv } = await encryptJson(userKey, { title, username, password, url, notes });
      await axios.post('/api/passwords', { encrypted_data: data, data_iv: iv, category_id: category_id || null });
      handleNewPasswordClose();
      // A full page reload would wipe the in-memory vault key and re-lock
      // the vault - notify the already-mounted Dashboard instead.
      window.dispatchEvent(new Event('passwordsChanged'));
    } catch (error) {
      setError(error.response?.data?.error || 'Failed to create password');
    }
  };

  const handleInputChange = (event) => {
    const { name, value } = event.target;
    setNewPassword(prev => ({
      ...prev,
      [name]: value
    }));

    if (name === 'password') {
      setPasswordStrength(calculatePasswordStrength(value));
    }
  };

  const handleGeneratorSettingChange = (event) => {
    const { name, value, checked } = event.target;
    setGeneratorSettings(prev => ({
      ...prev,
      [name]: name === 'length' ? value : checked
    }));
  };

  useEffect(() => {
    if (openNewPasswordDialog) {
      generatePassword();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [generatorSettings, openNewPasswordDialog]);

  const handleCopyPassword = () => {
    navigator.clipboard.writeText(newPassword.password);
    setShowCopiedMessage(true);
    setTimeout(() => setShowCopiedMessage(false), 2000);
  };

  const navItems = [
    { path: '/dashboard', label: 'Dashboard', icon: <FolderIcon /> },
    { path: '/tools', label: 'Tools', icon: <FolderIcon /> },
    { path: '/stats', label: 'Statistiken', icon: <AssessmentIcon /> },
    { path: '/history', label: 'Verlauf', icon: <HistoryIcon /> },
  ];

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', minHeight: '100vh' }}>
      <AppBar
        position="fixed"
        sx={{
          zIndex: (theme) => theme.zIndex.drawer + 1,
          bgcolor: '#FFFFFF',
          borderBottom: '1px solid #E5E7EB',
          boxShadow: '0 1px 2px 0 rgba(0, 0, 0, 0.05)',
        }}
      >
        <Toolbar>
          {isMobile && (
            <IconButton onClick={() => setMobileNavOpen(true)} sx={{ color: '#6B7280', mr: 1 }}>
              <MenuIcon />
            </IconButton>
          )}

          <Box
            component={Link}
            to="/"
            sx={{
              display: 'flex',
              alignItems: 'center',
              gap: 1,
              textDecoration: 'none',
              mr: { xs: 1, sm: 4 },
            }}
          >
            <SecurityIcon sx={{ color: '#2563EB', fontSize: 28 }} />
            {!isMobile && (
              <Typography
                variant="h6"
                sx={{
                  color: '#111827',
                  fontWeight: 700,
                  letterSpacing: '-0.02em',
                }}
              >
                Winkey
              </Typography>
            )}
          </Box>

          <Box sx={{ flexGrow: 1, display: { xs: 'none', sm: 'flex' }, gap: 0.5 }}>
            {navItems.map((item) => (
              <Button
                key={item.path}
                component={Link}
                to={item.path}
                variant="text"
                startIcon={item.icon}
                sx={{
                  color: location.pathname === item.path ? '#2563EB' : '#6B7280',
                  minWidth: 'auto',
                  px: 1.5,
                  '&:hover': {
                    color: '#111827',
                    bgcolor: 'rgba(37, 99, 235, 0.06)',
                  },
                }}
              >
                {item.label}
              </Button>
            ))}
          </Box>

          <Box sx={{ flexGrow: isMobile ? 1 : 0 }} />

          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Button
              variant="contained"
              startIcon={<AddIcon />}
              onClick={handleNewPasswordClick}
              sx={{
                bgcolor: '#2563EB',
                color: 'white',
                '&:hover': {
                  bgcolor: '#1D4ED8',
                },
              }}
            >
              Neu
            </Button>

            <IconButton
              onClick={toggleDarkMode}
              sx={{ color: '#6B7280' }}
            >
              {darkMode ? <Brightness7 /> : <Brightness4 />}
            </IconButton>

            <IconButton
              onClick={handleMenu}
              sx={{ color: '#6B7280' }}
            >
              <AccountCircle />
            </IconButton>
            <Menu
              anchorEl={anchorEl}
              open={Boolean(anchorEl)}
              onClose={handleClose}
              onClick={handleClose}
            >
              <MenuItem onClick={handleLogout}>Logout</MenuItem>
            </Menu>
          </Box>
        </Toolbar>
      </AppBar>

      <Drawer anchor="left" open={mobileNavOpen} onClose={() => setMobileNavOpen(false)}>
        <Box sx={{ width: 260 }} role="presentation" onClick={() => setMobileNavOpen(false)}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, p: 2 }}>
            <SecurityIcon sx={{ color: '#2563EB', fontSize: 28 }} />
            <Typography variant="h6" sx={{ fontWeight: 700 }}>Winkey</Typography>
          </Box>
          <List>
            {navItems.map((item) => (
              <ListItemButton
                key={item.path}
                component={Link}
                to={item.path}
                selected={location.pathname === item.path}
              >
                <ListItemIcon>{item.icon}</ListItemIcon>
                <ListItemText primary={item.label} />
              </ListItemButton>
            ))}
          </List>
        </Box>
      </Drawer>

      {/* New Password Dialog */}
      <Dialog
        open={openNewPasswordDialog}
        onClose={handleNewPasswordClose}
        maxWidth="sm"
        fullWidth
        fullScreen={isMobile}
      >
        <DialogTitle>Neues Passwort erstellen</DialogTitle>
        <DialogContent>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, pt: 2 }}>
            {error && (
              <Alert severity="error" sx={{ mb: 1 }}>
                {error}
              </Alert>
            )}
            <TextField
              margin="normal"
              required
              fullWidth
              label="Title"
              value={newPassword.title}
              onChange={(e) => setNewPassword(prev => ({ ...prev, title: e.target.value }))}
              error={!newPassword.title}
              helperText={!newPassword.title ? 'Title is required' : ''}
            />

            <TextField
              margin="normal"
              fullWidth
              label="Benutzername"
              name="username"
              value={newPassword.username}
              onChange={handleInputChange}
            />

            <FormControl fullWidth margin="normal">
              <InputLabel id="category-label">Kategorie</InputLabel>
              <Select
                labelId="category-label"
                value={newPassword.category_id}
                onChange={(e) => setNewPassword(prev => ({ ...prev, category_id: e.target.value }))}
                label="Kategorie"
              >
                <MenuItem value="">
                  <em>Keine Kategorie</em>
                </MenuItem>
                {categories.map((category) => (
                  <MenuItem key={category.id} value={category.id}>
                    {category.name}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
            
            <FormControl 
              fullWidth 
              margin="normal"
              error={!newPassword.password}
            >
              <InputLabel htmlFor="password">Passwort</InputLabel>
              <OutlinedInput
                id="password"
                name="password"
                type={showPassword ? 'text' : 'password'}
                value={newPassword.password}
                onChange={(e) => setNewPassword(prev => ({ ...prev, password: e.target.value }))}
                endAdornment={
                  <InputAdornment position="end">
                    <Tooltip title="Passwort kopieren">
                      <IconButton onClick={handleCopyPassword} edge="end" sx={{ mr: 1 }}>
                        <ContentCopyIcon />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="Neues Passwort generieren">
                      <IconButton onClick={generatePassword} edge="end" sx={{ mr: 1 }}>
                        <RefreshIcon />
                      </IconButton>
                    </Tooltip>
                    <IconButton
                      onClick={() => setShowPassword(!showPassword)}
                      edge="end"
                    >
                      {showPassword ? <VisibilityOff /> : <Visibility />}
                    </IconButton>
                  </InputAdornment>
                }
                label="Passwort"
              />
              {!newPassword.password && (
                <FormHelperText error>Password is required</FormHelperText>
              )}
              <FormHelperText>
                Stärke: {passwordStrength.label}
              </FormHelperText>
            </FormControl>

            <LinearProgress 
              variant="determinate" 
              value={passwordStrength.score}
              color={passwordStrength.color}
              sx={{ height: 8, borderRadius: 4 }}
            />

            {/* Password Generator Settings */}
            <Box sx={{ mt: 2 }}>
              <Typography variant="subtitle2" gutterBottom>
                Passwort-Generator Einstellungen
              </Typography>
              <Box sx={{ px: 2 }}>
                <Typography id="password-length-slider" gutterBottom>
                  Länge: {generatorSettings.length} Zeichen
                </Typography>
                <Slider
                  name="length"
                  value={generatorSettings.length}
                  onChange={(_, value) => handleGeneratorSettingChange({ target: { name: 'length', value }})}
                  min={8}
                  max={64}
                  aria-labelledby="password-length-slider"
                />
                <FormControlLabel
                  control={
                    <Checkbox
                      checked={generatorSettings.uppercase}
                      onChange={handleGeneratorSettingChange}
                      name="uppercase"
                    />
                  }
                  label="Großbuchstaben (A-Z)"
                />
                <FormControlLabel
                  control={
                    <Checkbox
                      checked={generatorSettings.lowercase}
                      onChange={handleGeneratorSettingChange}
                      name="lowercase"
                    />
                  }
                  label="Kleinbuchstaben (a-z)"
                />
                <FormControlLabel
                  control={
                    <Checkbox
                      checked={generatorSettings.numbers}
                      onChange={handleGeneratorSettingChange}
                      name="numbers"
                    />
                  }
                  label="Zahlen (0-9)"
                />
                <FormControlLabel
                  control={
                    <Checkbox
                      checked={generatorSettings.special}
                      onChange={handleGeneratorSettingChange}
                      name="special"
                    />
                  }
                  label="Sonderzeichen (!@#$%^&*)"
                />
              </Box>
            </Box>

            <TextField
              name="url"
              label="URL"
              value={newPassword.url}
              onChange={handleInputChange}
              fullWidth
            />

            <TextField
              name="notes"
              label="Notizen"
              value={newPassword.notes}
              onChange={handleInputChange}
              fullWidth
              multiline
              rows={4}
            />

            {showCopiedMessage && (
              <Alert severity="success" sx={{ mt: 1 }}>
                Passwort wurde in die Zwischenablage kopiert
              </Alert>
            )}
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleNewPasswordClose}>Abbrechen</Button>
          <Button onClick={handleNewPasswordSubmit} variant="contained">
            Speichern
          </Button>
        </DialogActions>
      </Dialog>

      <Toolbar /> {/* Spacer */}
      <Container maxWidth="xl" sx={{ flex: 1, py: 3 }}>
        <Outlet />
      </Container>
    </Box>
  );
}