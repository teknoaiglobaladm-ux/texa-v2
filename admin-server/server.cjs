const http = require('http');
const { URL } = require('url');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const loadEnvFile = (filePath) => {
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    for (const rawLine of content.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line) continue;
      if (line.startsWith('#')) continue;
      const idx = line.indexOf('=');
      if (idx <= 0) continue;
      const key = line.slice(0, idx).trim();
      let value = line.slice(idx + 1).trim();
      if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
        value = value.slice(1, -1);
      }
      if (process.env[key] === undefined) process.env[key] = value;
    }
  } catch {
  }
};

loadEnvFile(path.resolve(process.cwd(), '.env.local'));
loadEnvFile(path.resolve(process.cwd(), '.env'));

// Supabase configuration
const SUPABASE_URL = process.env.VITE_SUPABASE_URL || process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.VITE_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

// TokoPay Configuration
const TOKOPAY_CONFIG = {
  merchantId: process.env.TOKOPAY_MERCHANT_ID || 'M250828KEAYY483',
  secretKey: process.env.TOKOPAY_SECRET_KEY || 'b3bb79b23b82ed33a54927dbaac95d8a70e19de7f5d47a613d1db4d32776125c',
  apiBaseUrl: 'https://api.tokopay.id/v1'
};

const ADMIN_EMAILS = new Set([
  'teknoaiglobal.adm@gmail.com'
]);

let adminReady = false;
let adminInitError = '';

// Check Supabase configuration
if (SUPABASE_URL && SUPABASE_ANON_KEY) {
  adminReady = true;
  console.log('✅ Supabase configured successfully');
  console.log(`   URL: ${SUPABASE_URL}`);
  if (SUPABASE_SERVICE_ROLE_KEY) {
    console.log('   Service Role Key: configured');
  } else {
    console.log('   ⚠️  Service Role Key: NOT configured (some features limited)');
  }
} else {
  adminInitError = 'Missing SUPABASE_URL or SUPABASE_ANON_KEY';
  console.error('❌ Supabase not configured:', adminInitError);
}

console.log('💳 TokoPay configured:', { merchantId: TOKOPAY_CONFIG.merchantId });

const json = (res, statusCode, body) => {
  const payload = JSON.stringify(body);
  res.writeHead(statusCode, {
    'content-type': 'application/json; charset=utf-8',
    'access-control-allow-origin': '*',
    'access-control-allow-methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS',
    'access-control-allow-headers': 'content-type,authorization,x-dev-bypass'
  });
  res.end(payload);
};

const readBody = (req) =>
  new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => {
      data += chunk;
      if (data.length > 2_000_000) req.destroy();
    });
    req.on('end', () => {
      if (!data) return resolve({});
      try {
        resolve(JSON.parse(data));
      } catch (e) {
        reject(e);
      }
    });
    req.on('error', reject);
  });

const getBearerToken = (req) => {
  const authHeader = req.headers.authorization || '';
  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  return match ? match[1] : null;
};

// Fetch wrapper for Supabase API calls
const supabaseFetch = async (endpoint, options = {}) => {
  const url = `${SUPABASE_URL}${endpoint}`;
  const headers = {
    'Content-Type': 'application/json',
    'apikey': SUPABASE_SERVICE_ROLE_KEY || SUPABASE_ANON_KEY,
    'Authorization': `Bearer ${SUPABASE_SERVICE_ROLE_KEY || SUPABASE_ANON_KEY}`,
    ...options.headers
  };

  const response = await fetch(url, {
    ...options,
    headers
  });

  return response;
};

// Verify JWT token from Supabase
const verifySupabaseToken = async (token) => {
  try {
    const response = await supabaseFetch('/auth/v1/user', {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });

    if (!response.ok) return null;

    const user = await response.json();
    return user;
  } catch (error) {
    console.error('Token verification error:', error);
    return null;
  }
};

const requireAdmin = async (req) => {
  if (!adminReady) return { ok: false, status: 500, message: 'Admin server belum dikonfigurasi' };

  const token = getBearerToken(req);
  if (!token) return { ok: false, status: 401, message: 'Unauthorized' };

  const user = await verifySupabaseToken(token);
  if (!user || !user.email) {
    return { ok: false, status: 401, message: 'Unauthorized' };
  }

  const email = user.email.toLowerCase();
  if (ADMIN_EMAILS.has(email)) return { ok: true, uid: user.id, email };

  // Also check user metadata for admin role
  const role = user.user_metadata?.role || user.app_metadata?.role;
  if (role === 'ADMIN') return { ok: true, uid: user.id, email };

  return { ok: false, status: 403, message: 'Forbidden' };
};

// For development mode - allow bypass
const requireAdminOrDev = async (req) => {
  // Check if in dev mode
  const isDev = process.env.NODE_ENV !== 'production';
  const devBypass = req.headers['x-dev-bypass'] === 'true';

  if (isDev && devBypass) {
    return { ok: true, uid: 'dev-mode', email: 'dev@localhost' };
  }

  return requireAdmin(req);
};

const normalizeEmail = (email) => (email || '').trim().toLowerCase();

const computeSubscriptionEnd = (days) => {
  const durationDays = Number(days);
  if (!Number.isFinite(durationDays) || durationDays <= 0) return null;
  const start = new Date();
  const end = new Date(start);
  end.setDate(start.getDate() + durationDays);
  return { start, end, durationDays };
};

// ==================== TokoPay API Handler ====================

const handleTokopayCreateOrder = async (req, res) => {
  const body = await readBody(req);
  const { refId, nominal, metode, userId, userEmail, type, itemId, itemName, duration } = body;

  // Validate required fields
  if (!refId || !nominal || !metode) {
    return json(res, 400, {
      success: false,
      error: 'Missing required fields: refId, nominal, metode'
    });
  }

  try {
    // Build TokoPay API URL
    const params = new URLSearchParams({
      merchant: TOKOPAY_CONFIG.merchantId,
      secret: TOKOPAY_CONFIG.secretKey,
      ref_id: refId,
      nominal: nominal.toString(),
      metode: metode
    });

    const apiUrl = `${TOKOPAY_CONFIG.apiBaseUrl}/order?${params.toString()}`;
    console.log('📤 Calling TokoPay API:', { refId, nominal, metode });

    // Call TokoPay API
    const tokopayResponse = await fetch(apiUrl);
    const tokopayResult = await tokopayResponse.json();

    console.log('📥 TokoPay Response:', tokopayResult);

    if (tokopayResult.status === 'Success') {
      // Save to Supabase if configured
      if (SUPABASE_URL && (SUPABASE_SERVICE_ROLE_KEY || SUPABASE_ANON_KEY)) {
        try {
          const now = new Date().toISOString();
          const insertData = {
            ref_id: refId,
            user_id: userId || 'anonymous',
            user_email: userEmail || 'anonymous@test.com',
            type: type || 'subscription',
            item_id: itemId || '',
            item_name: itemName || '',
            duration: Number.isFinite(Number(duration)) ? Number(duration) : 0,
            nominal,
            payment_method: metode,
            status: 'pending',
            tokopay_trx_id: tokopayResult.data.trx_id,
            pay_url: tokopayResult.data.pay_url,
            total_bayar: tokopayResult.data.total_bayar,
            total_diterima: tokopayResult.data.total_diterima,
            created_at: now,
            updated_at: now
          };

          const insertResponse = await supabaseFetch('/rest/v1/orders', {
            method: 'POST',
            body: JSON.stringify(insertData)
          });

          if (!insertResponse.ok) {
            console.error('Error saving order to Supabase:', await insertResponse.text());
          } else {
            console.log('✅ Order saved to Supabase:', refId);
          }
        } catch (e) {
          console.error('Supabase order insert error:', e);
        }
      }

      return json(res, 200, {
        success: true,
        data: {
          refId: refId,
          payUrl: tokopayResult.data.pay_url,
          trxId: tokopayResult.data.trx_id,
          totalBayar: tokopayResult.data.total_bayar,
          totalDiterima: tokopayResult.data.total_diterima,
          qrLink: tokopayResult.data.qr_link || null,
          qrString: tokopayResult.data.qr_string || null,
          nomorVa: tokopayResult.data.nomor_va || null,
          checkoutUrl: tokopayResult.data.checkout_url || null
        }
      });
    } else {
      return json(res, 400, {
        success: false,
        error: tokopayResult.error_msg || tokopayResult.message || 'Failed to create order',
        details: tokopayResult
      });
    }

  } catch (error) {
    console.error('TokoPay Create Order Error:', error);
    return json(res, 500, {
      success: false,
      error: error.message || 'Internal server error'
    });
  }
};

const handleTokopayWebhook = async (req, res) => {
  try {
    const payload = await readBody(req);

    console.log('📨 TokoPay Webhook Received:', JSON.stringify(payload, null, 2));

    // Validate required fields
    if (!payload.reff_id || !payload.signature || !payload.status) {
      console.error('Missing required webhook fields');
      return json(res, 400, { status: false, error: 'Invalid payload' });
    }

    // Verify signature
    const signatureString = `${payload.data?.merchant_id || TOKOPAY_CONFIG.merchantId}:${TOKOPAY_CONFIG.secretKey}:${payload.reff_id}`;
    const expectedSignature = crypto.createHash('md5').update(signatureString).digest('hex');

    if (expectedSignature.toLowerCase() !== payload.signature.toLowerCase()) {
      console.error('Invalid signature received:', payload.signature, 'expected:', expectedSignature);
      return json(res, 401, { status: false, error: 'Invalid signature' });
    }

    // Check if payment is successful
    if (payload.status !== 'Success' && payload.status !== 'Completed') {
      console.log('Payment not successful:', payload.status);
      return json(res, 200, { status: true });
    }

    console.log('✅ Processing successful payment for ref_id:', payload.reff_id);

    // Update order in Supabase and activate subscription
    if (SUPABASE_URL && (SUPABASE_SERVICE_ROLE_KEY || SUPABASE_ANON_KEY)) {
      try {
        const now = new Date().toISOString();
        const updateData = {
          status: 'paid',
          tokopay_trx_id: payload.reference,
          total_bayar: payload.data?.total_dibayar,
          total_diterima: payload.data?.total_diterima,
          payment_method: payload.data?.payment_channel,
          updated_at: now,
          paid_at: now
        };

        const updateResponse = await supabaseFetch(`/rest/v1/orders?ref_id=eq.${payload.reff_id}`, {
          method: 'PATCH',
          body: JSON.stringify(updateData)
        });

        if (!updateResponse.ok) {
          console.error('Error updating order in Supabase:', await updateResponse.text());
        } else {
          console.log('✅ Order updated to PAID:', payload.reff_id);

          // Fetch order details to activate subscription
          const orderResponse = await supabaseFetch(`/rest/v1/orders?ref_id=eq.${payload.reff_id}&select=*`);
          if (orderResponse.ok) {
            const orders = await orderResponse.json();
            const order = orders[0];

            if (order && order.user_id && order.user_id !== 'anonymous' && order.user_id !== 'guest-user') {
              const duration = order.duration || 30;
              const sub = computeSubscriptionEnd(duration);

              if (sub) {
                // Update user's subscription_end
                const userUpdateResp = await supabaseFetch(`/rest/v1/users?id=eq.${order.user_id}`, {
                  method: 'PATCH',
                  body: JSON.stringify({
                    subscription_end: sub.end.toISOString(),
                    updated_at: now
                  })
                });

                if (userUpdateResp.ok) {
                  console.log('✅ User subscription activated:', order.user_id, 'until', sub.end.toISOString());
                } else {
                  console.error('Error updating user subscription:', await userUpdateResp.text());
                }

                // Create transaction record
                await supabaseFetch('/rest/v1/texa_transactions', {
                  method: 'POST',
                  body: JSON.stringify({
                    user_id: order.user_id,
                    user_email: order.user_email || 'unknown',
                    plan_name: order.item_name || 'Premium',
                    start_date: sub.start.toISOString(),
                    end_date: sub.end.toISOString(),
                    price: order.nominal || 0,
                    status: 'paid',
                    created_at: now
                  })
                });
                console.log('✅ Transaction record created for:', order.user_id);
              }
            } else {
              console.log('ℹ️ Guest checkout - no subscription to activate');
            }
          }
        }
      } catch (e) {
        console.error('Supabase order update error:', e);
      }
    }

    console.log('💰 Payment Success:', {
      refId: payload.reff_id,
      tokopayRef: payload.reference,
      amount: payload.data?.total_dibayar,
      received: payload.data?.total_diterima,
      channel: payload.data?.payment_channel
    });

    // Return success to TokoPay (REQUIRED)
    return json(res, 200, { status: true });

  } catch (error) {
    console.error('Webhook processing error:', error);
    // Still return success to prevent retry spam
    return json(res, 200, { status: true });
  }
};

// ==================== Admin Handlers ====================

// Create user using Supabase Admin API
const handleCreateUser = async (req, res) => {
  const guard = await requireAdminOrDev(req);
  if (!guard.ok) return json(res, guard.status, { success: false, message: guard.message });

  const body = await readBody(req);
  const email = normalizeEmail(body.email);
  const password = typeof body.password === 'string' ? body.password : '';
  const hasPassword = password.length > 0;
  const name = String(body.name || '').trim();
  const role = body.role === 'ADMIN' && ADMIN_EMAILS.has(email) ? 'ADMIN' : 'MEMBER';
  const isActive = body.isActive !== false;
  const sub = computeSubscriptionEnd(body.subscriptionDays);

  if (!email) return json(res, 400, { success: false, message: 'Email tidak valid' });
  if (hasPassword && password.length < 6) return json(res, 400, { success: false, message: 'Password minimal 6 karakter' });

  try {
    // Create user via Supabase Auth Admin API
    const createPassword = hasPassword ? password : crypto.randomBytes(18).toString('hex');

    const createResponse = await supabaseFetch('/auth/v1/admin/users', {
      method: 'POST',
      body: JSON.stringify({
        email,
        password: createPassword,
        email_confirm: true,
        user_metadata: {
          name: name || email,
          role
        }
      })
    });

    let uid;
    let action = 'created';

    if (createResponse.ok) {
      const userData = await createResponse.json();
      uid = userData.id;
    } else {
      const errorData = await createResponse.json();
      if (errorData.msg?.includes('already been registered') || errorData.code === 'email_exists') {
        // User exists, try to update
        action = 'updated';
        // First get the user
        const listResponse = await supabaseFetch(`/auth/v1/admin/users?email=${encodeURIComponent(email)}`);
        if (!listResponse.ok) {
          return json(res, 500, { success: false, message: 'Gagal mengambil data user' });
        }
        const users = await listResponse.json();
        const existingUser = users.users?.find(u => u.email.toLowerCase() === email);
        if (!existingUser) {
          return json(res, 404, { success: false, message: 'User tidak ditemukan' });
        }
        uid = existingUser.id;

        // Update user
        const updatePayload = {
          user_metadata: {
            name: name || existingUser.user_metadata?.name || email,
            role
          }
        };
        if (hasPassword) updatePayload.password = password;

        await supabaseFetch(`/auth/v1/admin/users/${uid}`, {
          method: 'PUT',
          body: JSON.stringify(updatePayload)
        });
      } else {
        console.error('Create user error:', errorData);
        return json(res, 500, { success: false, message: errorData.msg || 'Gagal membuat user' });
      }
    }

    // Update users table
    const nowIso = new Date().toISOString();
    const userTableData = {
      id: uid,
      email,
      name: name || email,
      role,
      subscription_end: sub ? sub.end.toISOString() : null,
      is_active: isActive,
      updated_at: nowIso
    };

    if (action === 'created') {
      userTableData.created_at = nowIso;
    }

    const upsertResponse = await supabaseFetch('/rest/v1/users', {
      method: 'POST',
      headers: {
        'Prefer': 'resolution=merge-duplicates'
      },
      body: JSON.stringify(userTableData)
    });

    if (!upsertResponse.ok) {
      console.error('Upsert user table error:', await upsertResponse.text());
    }

    // Record transaction if subscription
    if (sub) {
      await supabaseFetch('/rest/v1/texa_transactions', {
        method: 'POST',
        body: JSON.stringify({
          user_id: uid,
          user_email: email,
          plan_name: 'Manual',
          start_date: sub.start.toISOString(),
          end_date: sub.end.toISOString(),
          price: 0,
          status: 'active',
          created_at: nowIso
        })
      });
    }

    return json(res, 200, { success: true, uid, action });
  } catch (error) {
    console.error('Create user error:', error);
    return json(res, 500, { success: false, message: 'Gagal membuat user' });
  }
};

const handleSetPassword = async (req, res) => {
  const guard = await requireAdminOrDev(req);
  if (!guard.ok) return json(res, guard.status, { success: false, message: guard.message });

  const body = await readBody(req);
  const password = String(body.password || '');
  const email = body.email ? normalizeEmail(body.email) : null;
  const uid = body.uid ? String(body.uid) : null;

  if (password.length < 6) return json(res, 400, { success: false, message: 'Password minimal 6 karakter' });
  if (!email && !uid) return json(res, 400, { success: false, message: 'Target tidak valid' });

  try {
    let targetUid = uid;

    if (!targetUid && email) {
      // Get user by email
      const listResponse = await supabaseFetch(`/auth/v1/admin/users?email=${encodeURIComponent(email)}`);
      if (!listResponse.ok) {
        return json(res, 500, { success: false, message: 'Gagal mengambil data user' });
      }
      const users = await listResponse.json();
      const existingUser = users.users?.find(u => u.email.toLowerCase() === email);
      if (!existingUser) {
        return json(res, 404, { success: false, message: 'User tidak ditemukan' });
      }
      targetUid = existingUser.id;
    }

    // Update password
    const updateResponse = await supabaseFetch(`/auth/v1/admin/users/${targetUid}`, {
      method: 'PUT',
      body: JSON.stringify({ password })
    });

    if (!updateResponse.ok) {
      const errorData = await updateResponse.json();
      return json(res, 500, { success: false, message: errorData.msg || 'Gagal mengubah password' });
    }

    return json(res, 200, { success: true });
  } catch (error) {
    console.error('Set password error:', error);
    return json(res, 500, { success: false, message: 'Gagal mengubah password' });
  }
};

// Test database connection
const handleTestConnection = async (req, res) => {
  try {
    const response = await supabaseFetch('/rest/v1/', {
      method: 'GET'
    });

    if (response.ok) {
      return json(res, 200, {
        success: true,
        message: 'Koneksi database berhasil',
        supabaseUrl: SUPABASE_URL
      });
    } else {
      return json(res, 500, {
        success: false,
        message: 'Gagal terhubung ke database'
      });
    }
  } catch (error) {
    return json(res, 500, {
      success: false,
      message: `Error: ${error.message}`
    });
  }
};

// ==================== HTTP Server ====================

const server = http.createServer(async (req, res) => {
  const origin = req.headers.origin;
  if (origin) {
    res.setHeader('access-control-allow-origin', '*');
    res.setHeader('vary', 'origin');
  }
  res.setHeader('access-control-allow-methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  res.setHeader('access-control-allow-headers', 'content-type,authorization,x-dev-bypass');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    return res.end();
  }

  const url = new URL(req.url || '/', 'http://localhost');

  // Health check
  if (req.method === 'GET' && url.pathname === '/health') {
    return json(res, 200, {
      ok: true,
      adminReady,
      tokopayReady: true,
      adminInitError: adminReady ? undefined : adminInitError,
      backend: 'supabase'
    });
  }

  // Test connection
  if (req.method === 'GET' && url.pathname === '/test-connection') {
    return await handleTestConnection(req, res);
  }

  try {
    // TokoPay API Routes
    if (req.method === 'POST' && (url.pathname === '/api/tokopay/create-order' || url.pathname === '/tokopay/create-order')) {
      return await handleTokopayCreateOrder(req, res);
    }
    if (req.method === 'POST' && (url.pathname === '/api/tokopay/webhook' || url.pathname === '/tokopay/webhook')) {
      return await handleTokopayWebhook(req, res);
    }

    // Check payment status endpoint (for frontend polling)
    // IMPORTANT: This endpoint calls TokoPay API directly to check real payment status
    // because TokoPay webhook cannot reach localhost in dev mode
    if (req.method === 'GET' && (url.pathname === '/api/tokopay/check-status' || url.pathname === '/tokopay/check-status')) {
      const refId = url.searchParams.get('refId');
      if (!refId) {
        return json(res, 400, { success: false, error: 'Missing refId parameter' });
      }

      try {
        // First get order from Supabase
        const orderResp = await supabaseFetch(`/rest/v1/orders?ref_id=eq.${refId}&select=*`);
        let order = null;
        if (orderResp.ok) {
          const orders = await orderResp.json();
          order = orders[0];
        }

        // If order exists but still pending, check TokoPay API directly
        if (order && order.status === 'pending' && order.tokopay_trx_id) {
          console.log('🔍 [check-status] Checking TokoPay API for:', refId);
          console.log('🔍 [check-status] Order details:', {
            nominal: order.nominal,
            payment_method: order.payment_method,
            tokopay_trx_id: order.tokopay_trx_id
          });

          // Call TokoPay status check API
          // Format: https://api.tokopay.id/v1/order?merchant=XXX&secret=XXX&ref_id=XXX&nominal=XXX&metode=XXX
          const statusParams = new URLSearchParams({
            merchant: TOKOPAY_CONFIG.merchantId,
            secret: TOKOPAY_CONFIG.secretKey,
            ref_id: refId,
            nominal: String(order.nominal || 0),
            metode: order.payment_method || 'QRISREALTIME'
          });

          try {
            const tokopayStatusResp = await fetch(`${TOKOPAY_CONFIG.apiBaseUrl}/order?${statusParams.toString()}`);
            const tokopayStatus = await tokopayStatusResp.json();

            console.log('📥 TokoPay Full Response:', JSON.stringify(tokopayStatus, null, 2));
            console.log('📥 Response outer status:', tokopayStatus.status);
            console.log('📥 Response data:', tokopayStatus.data);
            console.log('📥 Response data.status:', tokopayStatus.data?.status);

            // TokoPay returns status: "Success" when API call succeeds, then check data.status for payment status
            if (tokopayStatus.status === 'Success' && tokopayStatus.data) {
              const paymentStatus = tokopayStatus.data.status; // "Paid", "Completed", "Unpaid", "Expired", "Failed"
              console.log('📥 Payment status from data.status:', paymentStatus);

              // Accept both "Paid" and "Completed" as successful payment
              if (paymentStatus === 'Paid' || paymentStatus === 'Completed') {
                console.log('✅ [check-status] TokoPay confirmed', paymentStatus, '! Updating order...');

                const now = new Date();
                const nowIso = now.toISOString();

                // Update order in Supabase to 'paid'
                const updateResp = await supabaseFetch(`/rest/v1/orders?ref_id=eq.${refId}`, {
                  method: 'PATCH',
                  body: JSON.stringify({
                    status: 'paid',
                    paid_at: nowIso,
                    updated_at: nowIso
                  })
                });
                console.log('📥 Supabase update response ok:', updateResp.ok);

                // Update local order object
                order.status = 'paid';
                order.paid_at = nowIso;

                console.log('✅ [check-status] Order updated to PAID:', refId);
              } else {
                console.log('⏳ [check-status] Payment status is:', paymentStatus, '- not yet paid');
              }
            } else {
              console.log('⚠️ [check-status] API status not Success or no data:', {
                apiStatus: tokopayStatus.status,
                hasData: !!tokopayStatus.data
              });
            }
          } catch (tokopayErr) {
            console.error('TokoPay status check error:', tokopayErr);
            // Continue with Supabase status
          }
        } else {
          console.log('🔍 [check-status] Order state:', {
            hasOrder: !!order,
            status: order?.status,
            hasTokopayTrxId: !!order?.tokopay_trx_id
          });
        }

        // If order is paid, check if activation is needed
        if (order && order.status === 'paid' && order.user_id && order.user_id !== 'anonymous' && order.user_id !== 'guest-user') {
          // Check if user's subscription is already set
          const userResp = await supabaseFetch(`/rest/v1/users?id=eq.${order.user_id}&select=subscription_end`);
          const users = userResp.ok ? await userResp.json() : [];
          const user = users[0];

          // Check if activation is needed (subscription not set or expired)
          const now = new Date();
          const isSubscription = refId.startsWith('SUB');
          const isIndividual = refId.startsWith('TXA');

          // For subscription: check if subscription is not set or expired
          // For individual: always check user_tools table
          let needsActivation = false;

          if (isSubscription) {
            needsActivation = !user?.subscription_end || new Date(user.subscription_end) < now;
          } else if (isIndividual) {
            // Check if tool access already exists
            const toolResp = await supabaseFetch(`/rest/v1/user_tools?user_id=eq.${order.user_id}&tool_id=eq.${order.item_id}&select=access_end`);
            const tools = toolResp.ok ? await toolResp.json() : [];
            needsActivation = tools.length === 0 || new Date(tools[0].access_end) < now;
          }

          if (needsActivation) {
            const duration = order.duration || 30;
            const nowIso = now.toISOString();

            if (isSubscription) {
              // Activate subscription
              const sub = computeSubscriptionEnd(duration);
              if (sub) {
                const userUpdateResp = await supabaseFetch(`/rest/v1/users?id=eq.${order.user_id}`, {
                  method: 'PATCH',
                  body: JSON.stringify({
                    subscription_end: sub.end.toISOString(),
                    updated_at: nowIso
                  })
                });

                if (userUpdateResp.ok) {
                  console.log('✅ [check-status] Subscription activated for:', order.user_id, 'until', sub.end.toISOString());

                  // Create transaction record if not exists
                  await supabaseFetch('/rest/v1/texa_transactions', {
                    method: 'POST',
                    body: JSON.stringify({
                      user_id: order.user_id,
                      user_email: order.user_email || 'unknown',
                      plan_name: order.item_name || 'Premium',
                      start_date: sub.start.toISOString(),
                      end_date: sub.end.toISOString(),
                      price: order.nominal || 0,
                      status: 'paid',
                      created_at: nowIso
                    })
                  });
                }
              }
            } else if (isIndividual && order.item_id) {
              // Activate individual tool
              const accessEnd = new Date();
              accessEnd.setDate(accessEnd.getDate() + (duration || 7));

              console.log('🔧 [check-status] Attempting to insert user_tool:', {
                user_id: order.user_id,
                tool_id: order.item_id,
                access_end: accessEnd.toISOString()
              });

              // Try upsert first
              const toolInsertResp = await supabaseFetch('/rest/v1/user_tools', {
                method: 'POST',
                headers: { 'Prefer': 'return=representation' },
                body: JSON.stringify({
                  user_id: order.user_id,
                  tool_id: order.item_id,
                  access_end: accessEnd.toISOString(),
                  order_ref_id: refId
                })
              });

              if (toolInsertResp.ok) {
                const inserted = await toolInsertResp.json();
                console.log('✅ [check-status] Individual tool activated:', order.item_id, 'for', order.user_id, inserted);
              } else {
                const errText = await toolInsertResp.text();
                console.error('❌ [check-status] Failed to insert user_tools:', errText);

                // If it's a duplicate key error, try update instead
                if (errText.includes('duplicate') || errText.includes('unique')) {
                  console.log('🔄 [check-status] Trying PATCH instead...');
                  const patchResp = await supabaseFetch(`/rest/v1/user_tools?user_id=eq.${order.user_id}&tool_id=eq.${order.item_id}`, {
                    method: 'PATCH',
                    body: JSON.stringify({
                      access_end: accessEnd.toISOString(),
                      order_ref_id: refId
                    })
                  });
                  if (patchResp.ok) {
                    console.log('✅ [check-status] User tool access updated via PATCH');
                  } else {
                    console.error('❌ [check-status] PATCH also failed:', await patchResp.text());
                  }
                }
              }
            }
          }
        }

        return json(res, 200, {
          success: true,
          status: order?.status || 'pending',
          paidAt: order?.paid_at || null,
          itemName: order?.item_name || null,
          duration: order?.duration || null,
          activated: order?.status === 'paid'
        });
      } catch (e) {
        console.error('Check status error:', e);
        return json(res, 200, { success: true, status: 'pending' });
      }
    }

    // ==================== Database Migration Endpoint ====================
    // Run this once to add new pricing columns
    if (req.method === 'POST' && url.pathname === '/api/admin/migrate-pricing') {
      const guard = await requireAdminOrDev(req);
      if (!guard.ok) return json(res, guard.status, { success: false, message: guard.message });

      try {
        // Add pricing columns using PATCH to update schema
        // Since Supabase REST API doesn't support ALTER TABLE, 
        // we'll just ensure new columns work by testing insert/update

        // Get a test tool first
        const testResp = await supabaseFetch('/rest/v1/tools?select=id&limit=1');
        if (!testResp.ok) {
          return json(res, 500, { success: false, message: 'Could not access tools table' });
        }

        const tools = await testResp.json();
        if (tools.length === 0) {
          return json(res, 200, {
            success: true,
            message: 'No tools to test. Please add columns manually in Supabase.'
          });
        }

        // Try to update with new columns - this will fail gracefully if columns don't exist
        const testUpdate = await supabaseFetch(`/rest/v1/tools?id=eq.${tools[0].id}`, {
          method: 'PATCH',
          body: JSON.stringify({
            price_7_days: tools[0].price_7_days || 0,
            price_14_days: tools[0].price_14_days || 0,
            price_30_days: tools[0].price_30_days || 0
          })
        });

        if (testUpdate.ok) {
          return json(res, 200, {
            success: true,
            message: 'Pricing columns exist and working!',
            note: 'You can now set per-tool pricing in Admin Dashboard'
          });
        } else {
          const errorText = await testUpdate.text();
          return json(res, 200, {
            success: false,
            message: 'Columns do not exist yet. Please add them in Supabase SQL Editor.',
            sql: `ALTER TABLE tools ADD COLUMN IF NOT EXISTS price_7_days INTEGER DEFAULT 0;
ALTER TABLE tools ADD COLUMN IF NOT EXISTS price_14_days INTEGER DEFAULT 0;
ALTER TABLE tools ADD COLUMN IF NOT EXISTS price_30_days INTEGER DEFAULT 0;`,
            error: errorText
          });
        }
      } catch (e) {
        console.error('Migration error:', e);
        return json(res, 500, { success: false, message: e.message });
      }
    }

    // ==================== Admin User CRUD Routes ====================

    // Get all users
    if (req.method === 'GET' && url.pathname === '/api/admin/users') {
      const guard = await requireAdminOrDev(req);
      if (!guard.ok) return json(res, guard.status, { success: false, message: guard.message });

      try {
        const response = await supabaseFetch('/rest/v1/users?select=*&order=created_at.desc');
        if (response.ok) {
          const users = await response.json();
          return json(res, 200, { success: true, data: users });
        } else {
          return json(res, 500, { success: false, message: 'Gagal mengambil data users' });
        }
      } catch (e) {
        console.error('Get users error:', e);
        return json(res, 500, { success: false, message: 'Server error' });
      }
    }

    // ==================== Admin Tool CRUD Routes ====================
    if (req.method === 'GET' && url.pathname === '/api/admin/tools') {
      const guard = await requireAdminOrDev(req);
      if (!guard.ok) return json(res, guard.status, { success: false, message: guard.message });

      try {
        const response = await supabaseFetch('/rest/v1/tools?select=*&order=sort_order.asc');
        if (response.ok) {
          const tools = await response.json();
          return json(res, 200, { success: true, data: tools });
        } else {
          return json(res, 500, { success: false, message: 'Gagal mengambil data tools' });
        }
      } catch (e) {
        console.error('Get tools error:', e);
        return json(res, 500, { success: false, message: 'Server error' });
      }
    }

    // Create tool
    if (req.method === 'POST' && url.pathname === '/api/admin/tools') {
      const guard = await requireAdminOrDev(req);
      if (!guard.ok) return json(res, guard.status, { success: false, message: guard.message });

      const body = await readBody(req);
      const { name, description, category, imageUrl, targetUrl, status, priceMonthly } = body;

      if (!name) {
        return json(res, 400, { success: false, message: 'Nama tool wajib diisi' });
      }

      try {
        const now = new Date().toISOString();

        // Get max sort_order
        const orderResp = await supabaseFetch('/rest/v1/tools?select=sort_order&order=sort_order.desc&limit=1');
        let maxOrder = 0;
        if (orderResp.ok) {
          const existing = await orderResp.json();
          maxOrder = existing[0]?.sort_order || 0;
        }

        const insertData = {
          name: name.trim(),
          description: description || '',
          category: category || '',
          image_url: imageUrl || '',
          tool_url: targetUrl || '',
          is_active: status === 'active',
          is_premium: true,
          price_monthly: Number(priceMonthly) || 0,
          sort_order: maxOrder + 1,
          created_at: now,
          updated_at: now,
          created_by: guard.email || 'admin'
        };

        const response = await supabaseFetch('/rest/v1/tools', {
          method: 'POST',
          headers: { 'Prefer': 'return=representation' },
          body: JSON.stringify(insertData)
        });

        if (response.ok) {
          const result = await response.json();
          console.log('✅ Tool created:', name);
          return json(res, 200, { success: true, data: result[0], id: result[0]?.id });
        } else {
          const err = await response.text();
          console.error('Create tool error:', err);
          return json(res, 500, { success: false, message: 'Gagal menambahkan tool' });
        }
      } catch (e) {
        console.error('Create tool error:', e);
        return json(res, 500, { success: false, message: 'Server error' });
      }
    }

    // Update tool
    if (req.method === 'PUT' && url.pathname.startsWith('/api/admin/tools/')) {
      const guard = await requireAdminOrDev(req);
      if (!guard.ok) return json(res, guard.status, { success: false, message: guard.message });

      const toolId = url.pathname.split('/').pop();
      if (!toolId) {
        return json(res, 400, { success: false, message: 'Tool ID wajib' });
      }

      const body = await readBody(req);
      const updateData = {
        updated_at: new Date().toISOString()
      };

      if (body.name !== undefined) updateData.name = body.name.trim();
      if (body.description !== undefined) updateData.description = body.description;
      if (body.category !== undefined) updateData.category = body.category;
      if (body.imageUrl !== undefined) updateData.image_url = body.imageUrl;
      if (body.targetUrl !== undefined) updateData.tool_url = body.targetUrl;
      if (body.status !== undefined) updateData.is_active = body.status === 'active';
      if (body.priceMonthly !== undefined) updateData.price_monthly = Number(body.priceMonthly) || 0;
      if (body.order !== undefined) updateData.sort_order = Number(body.order) || 0;
      // Multi-tier pricing fields
      if (body.price7Days !== undefined) updateData.price_7_days = Number(body.price7Days) || 0;
      if (body.price14Days !== undefined) updateData.price_14_days = Number(body.price14Days) || 0;
      if (body.price30Days !== undefined) updateData.price_30_days = Number(body.price30Days) || 0;

      try {
        const response = await supabaseFetch(`/rest/v1/tools?id=eq.${toolId}`, {
          method: 'PATCH',
          body: JSON.stringify(updateData)
        });

        if (response.ok) {
          console.log('✅ Tool updated:', toolId);
          return json(res, 200, { success: true });
        } else {
          const err = await response.text();
          console.error('Update tool error:', err);
          return json(res, 500, { success: false, message: 'Gagal mengupdate tool' });
        }
      } catch (e) {
        console.error('Update tool error:', e);
        return json(res, 500, { success: false, message: 'Server error' });
      }
    }

    // Delete tool
    if (req.method === 'DELETE' && url.pathname.startsWith('/api/admin/tools/')) {
      const guard = await requireAdminOrDev(req);
      if (!guard.ok) return json(res, guard.status, { success: false, message: guard.message });

      const toolId = url.pathname.split('/').pop();
      if (!toolId) {
        return json(res, 400, { success: false, message: 'Tool ID wajib' });
      }

      try {
        const response = await supabaseFetch(`/rest/v1/tools?id=eq.${toolId}`, {
          method: 'DELETE'
        });

        if (response.ok) {
          console.log('✅ Tool deleted:', toolId);
          return json(res, 200, { success: true });
        } else {
          const err = await response.text();
          console.error('Delete tool error:', err);
          return json(res, 500, { success: false, message: 'Gagal menghapus tool' });
        }
      } catch (e) {
        console.error('Delete tool error:', e);
        return json(res, 500, { success: false, message: 'Server error' });
      }
    }

    // Seed catalog data - restore mockup tools
    if (req.method === 'POST' && url.pathname === '/api/admin/tools/seed') {
      const guard = await requireAdminOrDev(req);
      if (!guard.ok) return json(res, guard.status, { success: false, message: guard.message });

      try {
        const now = new Date().toISOString();

        const mockupTools = [
          {
            name: 'ChatGPT Plus (Shared)',
            description: 'Akses penuh ke GPT-4o, DALL·E 3, dan fitur analisis data tercanggih.',
            category: 'Menulis & Riset',
            image_url: 'https://images.unsplash.com/photo-1677442136019-21780ecad995?auto=format&fit=crop&q=80&w=400',
            tool_url: 'https://chat.openai.com',
            is_active: true,
            is_premium: true,
            price_monthly: 45000,
            sort_order: 0,
            created_at: now,
            updated_at: now,
            created_by: 'system'
          },
          {
            name: 'Midjourney Pro',
            description: 'Generate gambar AI kualitas tinggi tanpa batas dengan mode cepat.',
            category: 'Desain & Art',
            image_url: 'https://images.unsplash.com/photo-1618005182384-a83a8bd57fbe?auto=format&fit=crop&q=80&w=400',
            tool_url: 'https://midjourney.com',
            is_active: true,
            is_premium: true,
            price_monthly: 75000,
            sort_order: 1,
            created_at: now,
            updated_at: now,
            created_by: 'system'
          },
          {
            name: 'Canva Pro Teams',
            description: 'Buka jutaan aset premium dan hapus background otomatis.',
            category: 'Desain Grafis',
            image_url: 'https://images.unsplash.com/photo-1626785774573-4b799315345d?auto=format&fit=crop&q=80&w=400',
            tool_url: 'https://canva.com',
            is_active: true,
            is_premium: true,
            price_monthly: 15000,
            sort_order: 2,
            created_at: now,
            updated_at: now,
            created_by: 'system'
          },
          {
            name: 'Jasper AI Business',
            description: 'Bikin konten sosmed dan iklan 10x lebih cepat dengan AI.',
            category: 'Marketing',
            image_url: 'https://images.unsplash.com/photo-1460925895917-afdab827c52f?auto=format&fit=crop&q=80&w=400',
            tool_url: 'https://jasper.ai',
            is_active: true,
            is_premium: true,
            price_monthly: 99000,
            sort_order: 3,
            created_at: now,
            updated_at: now,
            created_by: 'system'
          },
          {
            name: 'Claude 3.5 Sonnet',
            description: 'AI cerdas untuk coding dan penulisan kreatif dengan konteks luas.',
            category: 'Coding & Teks',
            image_url: 'https://images.unsplash.com/photo-1620712943543-bcc4688e7485?auto=format&fit=crop&q=80&w=400',
            tool_url: 'https://claude.ai',
            is_active: true,
            is_premium: true,
            price_monthly: 55000,
            sort_order: 4,
            created_at: now,
            updated_at: now,
            created_by: 'system'
          },
          {
            name: 'Grammarly Premium',
            description: 'Cek tata bahasa Inggris otomatis dan kirim email tanpa typo.',
            category: 'Produktivitas',
            image_url: 'https://images.unsplash.com/photo-1455390582262-044cdead277a?auto=format&fit=crop&q=80&w=400',
            tool_url: 'https://grammarly.com',
            is_active: true,
            is_premium: true,
            price_monthly: 25000,
            sort_order: 5,
            created_at: now,
            updated_at: now,
            created_by: 'system'
          }
        ];

        // Insert all mockup tools
        const response = await supabaseFetch('/rest/v1/tools', {
          method: 'POST',
          headers: { 'Prefer': 'return=representation' },
          body: JSON.stringify(mockupTools)
        });

        if (response.ok) {
          const result = await response.json();
          console.log('✅ Catalog mockup seeded:', result.length, 'tools');
          return json(res, 200, {
            success: true,
            message: `Berhasil menambahkan ${result.length} tools`,
            count: result.length
          });
        } else {
          const err = await response.text();
          console.error('Seed catalog error:', err);
          return json(res, 500, { success: false, message: 'Gagal seed catalog' });
        }
      } catch (e) {
        console.error('Seed catalog error:', e);
        return json(res, 500, { success: false, message: 'Server error' });
      }
    }

    // ==================== Settings CRUD Routes ====================

    // Get a setting by key
    if (req.method === 'GET' && url.pathname === '/api/admin/settings') {
      const guard = await requireAdminOrDev(req);
      if (!guard.ok) return json(res, guard.status, { success: false, message: guard.message });

      const key = url.searchParams.get('key');
      if (!key) {
        return json(res, 400, { success: false, message: 'Key parameter required' });
      }

      try {
        const response = await supabaseFetch(`/rest/v1/settings?key=eq.${encodeURIComponent(key)}&select=*`);
        if (response.ok) {
          const settings = await response.json();
          if (settings.length > 0) {
            return json(res, 200, { success: true, data: settings[0] });
          } else {
            return json(res, 200, { success: true, data: null });
          }
        } else {
          return json(res, 500, { success: false, message: 'Gagal mengambil settings' });
        }
      } catch (e) {
        console.error('Get settings error:', e);
        return json(res, 500, { success: false, message: 'Server error' });
      }
    }

    // Save/Update a setting
    if (req.method === 'PUT' && url.pathname === '/api/admin/settings') {
      const guard = await requireAdminOrDev(req);
      if (!guard.ok) return json(res, guard.status, { success: false, message: guard.message });

      const body = await readBody(req);
      const { key, value } = body;

      if (!key) {
        return json(res, 400, { success: false, message: 'Key is required' });
      }

      try {
        const now = new Date().toISOString();

        // First check if setting exists
        const existsResp = await supabaseFetch(`/rest/v1/settings?key=eq.${encodeURIComponent(key)}&select=key`);
        const existsData = existsResp.ok ? await existsResp.json() : [];
        const exists = existsData.length > 0;

        let response;
        if (exists) {
          // Update existing
          response = await supabaseFetch(`/rest/v1/settings?key=eq.${encodeURIComponent(key)}`, {
            method: 'PATCH',
            body: JSON.stringify({
              value: value || {},
              updated_at: now
            })
          });
        } else {
          // Insert new
          response = await supabaseFetch('/rest/v1/settings', {
            method: 'POST',
            body: JSON.stringify({
              key,
              value: value || {},
              updated_at: now
            })
          });
        }

        if (response.ok) {
          console.log('✅ Setting saved:', key);
          return json(res, 200, { success: true, message: 'Setting saved' });
        } else {
          const err = await response.text();
          console.error('Save setting error:', err);
          return json(res, 500, { success: false, message: 'Gagal menyimpan setting' });
        }
      } catch (e) {
        console.error('Save setting error:', e);
        return json(res, 500, { success: false, message: 'Server error' });
      }
    }

    // ==================== Footer Settings CRUD Routes ====================

    // Get footer settings
    if (req.method === 'GET' && url.pathname === '/api/admin/footer-settings') {
      const guard = await requireAdminOrDev(req);
      if (!guard.ok) return json(res, guard.status, { success: false, message: guard.message });

      try {
        const response = await supabaseFetch('/rest/v1/footer_settings?select=*&limit=1');
        if (response.ok) {
          const settings = await response.json();
          if (settings.length > 0) {
            return json(res, 200, { success: true, data: settings[0] });
          } else {
            return json(res, 200, { success: true, data: null });
          }
        } else {
          return json(res, 500, { success: false, message: 'Gagal mengambil footer settings' });
        }
      } catch (e) {
        console.error('Get footer settings error:', e);
        return json(res, 500, { success: false, message: 'Server error' });
      }
    }

    // Save/Update footer settings
    if (req.method === 'PUT' && url.pathname === '/api/admin/footer-settings') {
      const guard = await requireAdminOrDev(req);
      if (!guard.ok) return json(res, guard.status, { success: false, message: guard.message });

      const body = await readBody(req);

      try {
        const now = new Date().toISOString();
        const settingsData = {
          company_name: body.companyName,
          company_tagline: body.companyTagline,
          copyright_text: body.copyrightText,
          whatsapp_url: body.whatsappUrl,
          email: body.email,
          phone: body.phone,
          address_line1: body.addressLine1,
          address_line2: body.addressLine2,
          city: body.city,
          country: body.country,
          maps_url: body.mapsUrl,
          maps_embed_url: body.mapsEmbedUrl,
          social_media: body.socialMedia,
          updated_at: now
        };

        // First check if any record exists
        const existsResp = await supabaseFetch('/rest/v1/footer_settings?select=id&limit=1');
        const existsData = existsResp.ok ? await existsResp.json() : [];
        const exists = existsData.length > 0;

        let response;
        if (exists) {
          // Update existing
          response = await supabaseFetch(`/rest/v1/footer_settings?id=eq.${existsData[0].id}`, {
            method: 'PATCH',
            body: JSON.stringify(settingsData)
          });
        } else {
          // Insert new
          response = await supabaseFetch('/rest/v1/footer_settings', {
            method: 'POST',
            body: JSON.stringify(settingsData)
          });
        }

        if (response.ok) {
          console.log('✅ Footer settings saved');
          return json(res, 200, { success: true, message: 'Footer settings saved' });
        } else {
          const err = await response.text();
          console.error('Save footer settings error:', err);
          return json(res, 500, { success: false, message: 'Gagal menyimpan footer settings' });
        }
      } catch (e) {
        console.error('Save footer settings error:', e);
        return json(res, 500, { success: false, message: 'Server error' });
      }
    }

    // Admin API Routes
    if (req.method === 'POST' && (url.pathname === '/admin/create-user' || url.pathname === '/api/admin/create-user')) {
      return await handleCreateUser(req, res);
    }
    if (req.method === 'POST' && (url.pathname === '/admin/set-password' || url.pathname === '/api/admin/set-password')) {
      return await handleSetPassword(req, res);
    }
  } catch (error) {
    console.error('Server error:', error);
    return json(res, 500, { success: false, message: 'Server error' });
  }

  return json(res, 404, { success: false, message: 'Not found' });
});

const port = Number(process.env.ADMIN_PORT || 8787);
const host = process.env.ADMIN_HOST || '127.0.0.1';

server.listen(port, host, () => {
  console.log(`\n🚀 Admin + TokoPay Server running at http://${host}:${port}`);
  console.log(`   Backend: Supabase`);
  console.log(`   TokoPay API: http://${host}:${port}/api/tokopay/create-order`);
  console.log(`   Health: http://${host}:${port}/health`);
  console.log(`   Test DB: http://${host}:${port}/test-connection\n`);
});
