// server/src/secure/internalDispatcher.js
// Safe in-process router dispatcher for registered business operations.
// Eliminates network bypass and client-controlled dynamic routing.

const express = require('express');
const { URLSearchParams } = require('url');

const internalApiRouter = express.Router();
internalApiRouter.use('/workspaces', require('../routes/workspaces'));
internalApiRouter.use('/boards', require('../routes/boards'));
internalApiRouter.use('/lists', require('../routes/lists'));
internalApiRouter.use('/cards', require('../routes/cards'));
internalApiRouter.use('/archive', require('../routes/archive'));
internalApiRouter.use('/archived', require('../routes/archive'));
internalApiRouter.use('/attachments', require('../routes/attachments'));
internalApiRouter.use('/invitations', require('../routes/invitations'));
internalApiRouter.use('/notifications', require('../routes/notifications'));
internalApiRouter.use('/permissions', require('../routes/permissions'));
internalApiRouter.use('/roles', require('../routes/roles'));
internalApiRouter.use('/files', require('../routes/files'));
internalApiRouter.use('/push', require('../routes/push'));
internalApiRouter.use('/auth', require('../routes/auth'));
internalApiRouter.use('/', require('../routes/checkins'));

/**
 * Dispatches an operation to the internal router using a strictly hardcoded route & method.
 * Cookies set by internal routes (e.g. auth login, refresh, logout) are forwarded to ctx.res.
 */
function dispatchInternal(ctx, { method, url, body = {}, query = {} }) {
  return new Promise((resolve, reject) => {
    const req = ctx.req;
    const res = ctx.res;
    const requestId = req?.id || req?.headers?.['x-request-id'] || 'internal-req';

    const subReq = Object.create(req);
    subReq.method = method.toUpperCase();
    subReq.originalUrl = url;
    subReq.body = body || {};
    subReq.user = ctx.user || req.user || null;
    subReq.tenant = ctx.tenant || req.tenant || null;
    subReq.db = ctx.db || req.db || null;
    subReq.id = requestId;
    subReq.socket = req.socket;
    subReq.connection = req.connection;
    subReq.ip = req.ip || req.socket?.remoteAddress || '127.0.0.1';
    subReq.ips = req.ips || [];
    subReq.headers = {
      ...(req.headers || {}),
      'x-request-id': requestId
    };
    subReq.cookies = req.cookies || {};

    // Build query object
    let targetPath = url;
    const qIndex = url.indexOf('?');
    if (qIndex !== -1) {
      const searchParams = new URLSearchParams(url.substring(qIndex + 1));
      subReq.query = { ...Object.fromEntries(searchParams.entries()), ...query };
      targetPath = url.substring(0, qIndex);
    } else {
      subReq.query = { ...query };
    }

    // Strip leading /api
    if (targetPath.startsWith('/api/')) {
      subReq.url = targetPath.substring(4);
    } else if (targetPath === '/api') {
      subReq.url = '/';
    } else {
      subReq.url = targetPath;
    }
    subReq.baseUrl = '/api';

    let responseStatus = 200;
    let responseData = null;
    let ended = false;
    const headers = {};

    const subRes = {
      locals: (res && res.locals) ? res.locals : {},
      status(code) {
        responseStatus = code;
        return subRes;
      },
      sendStatus(code) {
        responseStatus = code;
        ended = true;
        resolve({ status: responseStatus, data: null });
        return subRes;
      },
      setHeader(name, val) {
        if (name) {
          headers[String(name).toLowerCase()] = val;
          try {
            res.setHeader(name, val);
          } catch (e) {}
        }
        return subRes;
      },
      getHeader(name) {
        return name ? headers[String(name).toLowerCase()] || null : null;
      },
      removeHeader(name) {
        if (name) {
          delete headers[String(name).toLowerCase()];
          try {
            res.removeHeader(name);
          } catch (e) {}
        }
        return subRes;
      },
      contentType() {
        return subRes;
      },
      type() {
        return subRes;
      },
      vary() {
        return subRes;
      },
      cookie(...args) {
        try {
          res.cookie(...args);
        } catch (e) {}
        return subRes;
      },
      clearCookie(...args) {
        try {
          res.clearCookie(...args);
        } catch (e) {}
        return subRes;
      },
      json(data) {
        if (ended) return;
        ended = true;
        responseData = data;
        if (responseStatus >= 400) {
          const err = new Error(data?.error?.message || data?.message || 'Operation failed');
          err.status = responseStatus;
          err.code = data?.error?.code || data?.code || 'ERROR';
          err.details = data?.error?.details || data?.details;
          err.data = data;
          return reject(err);
        }
        resolve(responseData);
      },
      send(data) {
        if (ended) return;
        ended = true;
        try {
          responseData = JSON.parse(data);
        } catch {
          responseData = data;
        }
        if (responseStatus >= 400) {
          const err = new Error(responseData?.error?.message || responseData?.message || 'Operation failed');
          err.status = responseStatus;
          err.code = responseData?.error?.code || 'ERROR';
          err.data = responseData;
          return reject(err);
        }
        resolve(responseData);
      },
      end() {
        if (ended) return;
        ended = true;
        resolve(responseData);
      }
    };

    try {
      internalApiRouter.handle(subReq, subRes, (err) => {
        if (err) {
          reject(err);
        } else if (!ended) {
          const notFoundErr = new Error(`Internal route ${method} ${url} not found`);
          notFoundErr.status = 404;
          notFoundErr.code = 'NOT_FOUND';
          reject(notFoundErr);
        }
      });
    } catch (dispatchErr) {
      reject(dispatchErr);
    }
  });
}

module.exports = {
  dispatchInternal,
  internalApiRouter
};

