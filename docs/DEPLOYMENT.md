# Deployment Guide

See root `docs/DEPLOYMENT.md` for complete documentation.

## Emergency Hotfix: `hotfix-l0` (Realtime Cross-Tenant Leak Fix)

### Production Deployment Procedure
1. **Fetch & Checkout Tag**:
   ```bash
   cd /var/www/pmt-backend
   git fetch --tags origin
   git checkout tags/hotfix-l0
   ```
2. **Restart Backend Service**:
   ```bash
   pm2 restart trello-backend
   pm2 logs trello-backend --lines 30
   ```

### Two-Company Verification Steps
1. **Setup**:
   - Sign in to **Company A** (`tenant 1`) in Browser 1 as User 1 and navigate to Board 1.
   - Sign in to **Company B** (`tenant 2`) in Browser 2 (or Incognito) as User 1 and navigate to Board 1 (colliding database IDs).
2. **Actions in Company A**:
   - In Browser 1, create a task "Company A Secret Card", move it to "In Progress", and post a comment.
3. **Assertions**:
   - Browser 1 updates in real-time instantly.
   - Browser 2 (**Company B**) receives **ZERO** socket events, no notifications, and no toasts.
   - Inspect server logs to confirm zero `[SOCKET_ERROR]` lines:
     ```bash
     pm2 logs trello-backend --lines 50 | grep SOCKET_ERROR
     ```
   - Run automated verification:
     ```bash
     npm run test:l0
     ```
