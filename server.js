
const express = require("express");
const path = require("path");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const PORT = process.env.PORT || 10000;

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

// =====================================================
// SUPABASE — RENDER ENVIRONMENT VARIABLES ONLY
// =====================================================

const SUPABASE_URL = process.env.SUPABASE_URL || "";

const SUPABASE_KEY =
    process.env.SUPABASE_SECRET_KEY ||
    process.env.SUPABASE_SERVICE_ROLE_KEY ||
    "";

const SESSION_SECRET =
    process.env.SESSION_SECRET ||
    crypto.randomBytes(32).toString("hex");

let supabase = null;

if (SUPABASE_URL && SUPABASE_KEY) {
    try {
        supabase = createClient(
            SUPABASE_URL,
            SUPABASE_KEY,
            {
                auth: {
                    autoRefreshToken: false,
                    persistSession: false
                }
            }
        );
    } catch (error) {
        console.error(
            "Supabase configuration error:",
            error.message
        );
    }
} else {
    console.error(
        "Missing SUPABASE_URL or SUPABASE_SECRET_KEY"
    );
}

// =====================================================
// SESSION
// =====================================================

function sign(value) {
    return crypto
        .createHmac("sha256", SESSION_SECRET)
        .update(value)
        .digest("base64url");
}

function makeSession(institutionId) {
    const payload = Buffer.from(
        JSON.stringify({
            institutionId: String(institutionId),
            exp: Date.now() + 12 * 60 * 60 * 1000
        })
    ).toString("base64url");

    return payload + "." + sign(payload);
}

function readCookies(req) {
    const cookies = {};

    for (const part of (req.headers.cookie || "").split(";")) {
        const index = part.indexOf("=");

        if (index === -1) continue;

        const key = part.slice(0, index).trim();
        const value = part.slice(index + 1).trim();

        try {
            cookies[key] = decodeURIComponent(value);
        } catch {
            // Ignore malformed cookies.
        }
    }

    return cookies;
}

function getSession(req) {
    const token = readCookies(req).institution_session;

    if (!token) return null;

    const parts = token.split(".");

    if (parts.length !== 2) return null;

    const [payload, signature] = parts;
    const expected = sign(payload);

    const actualBuffer = Buffer.from(signature);
    const expectedBuffer = Buffer.from(expected);

    if (
        actualBuffer.length !== expectedBuffer.length ||
        !crypto.timingSafeEqual(
            actualBuffer,
            expectedBuffer
        )
    ) {
        return null;
    }

    try {
        const data = JSON.parse(
            Buffer.from(
                payload,
                "base64url"
            ).toString("utf8")
        );

        if (
            !data.institutionId ||
            !Number.isFinite(Number(data.exp)) ||
            Number(data.exp) <= Date.now()
        ) {
            return null;
        }

        return data;
    } catch {
        return null;
    }
}

function setSessionCookie(req, res, institutionId) {
    const secure =
        req.secure ||
        req.headers["x-forwarded-proto"] === "https";

    res.cookie(
        "institution_session",
        makeSession(institutionId),
        {
            httpOnly: true,
            secure: Boolean(secure),
            sameSite: "lax",
            path: "/",
            maxAge: 12 * 60 * 60 * 1000
        }
    );
}

function clearSessionCookie(req, res) {
    const secure =
        req.secure ||
        req.headers["x-forwarded-proto"] === "https";

    res.clearCookie(
        "institution_session",
        {
            httpOnly: true,
            secure: Boolean(secure),
            sameSite: "lax",
            path: "/"
        }
    );
}

// =====================================================
// HEALTH CHECK
// =====================================================

app.get("/api/health", (req, res) => {
    res.json({
        success: true,
        server: "Institution Access",
        databaseConfigured: Boolean(supabase)
    });
});

// =====================================================
// LOGIN
// =====================================================

app.post("/api/login", async (req, res) => {
    try {
        if (!supabase) {
            return res.status(503).json({
                success: false,
                message:
                    "Supabase is not configured in Render Environment."
            });
        }

        const loginId = String(
            req.body?.loginId || ""
        ).trim();

        const password = String(
            req.body?.password || ""
        ).trim();

        if (!loginId || !password) {
            return res.status(400).json({
                success: false,
                message:
                    "Please enter login ID and password."
            });
        }

        const upperId = loginId.toUpperCase();

        // Query separately instead of building an
        // unescaped OR filter from user input.
        let result = await supabase
            .from("institutions")
            .select("*")
            .eq("institution_id", upperId)
            .eq("status", "active")
            .limit(1);

        if (result.error) {
            throw result.error;
        }

        let row = result.data?.[0];

        if (!row) {
            result = await supabase
                .from("institutions")
                .select("*")
                .eq("email", loginId)
                .eq("status", "active")
                .limit(1);

            if (result.error) {
                throw result.error;
            }

            row = result.data?.[0];
        }

        if (!row) {
            return res.status(401).json({
                success: false,
                message:
                    "Institution account not found."
            });
        }

        // Compatible with the existing
        // access_password column.
        if (
            String(row.access_password || "") !==
            password
        ) {
            return res.status(401).json({
                success: false,
                message: "Invalid login details."
            });
        }

        setSessionCookie(
            req,
            res,
            row.institution_id
        );

        return res.json({
            success: true,
            institution: {
                id: row.id,
                institution_id: row.institution_id,
                institution_type: row.institution_type,
                institution_name: row.institution_name,
                branches: row.branches,
                mobile: row.mobile,
                email: row.email,
                address: row.address,
                logo_url: row.logo_url
            }
        });

    } catch (error) {
        console.error(
            "LOGIN ERROR:",
            error.message
        );

        return res.status(500).json({
            success: false,
            message: "Login failed. Check Render logs."
        });
    }
});

// =====================================================
// LOGOUT
// =====================================================

app.post("/api/logout", (req, res) => {
    clearSessionCookie(req, res);

    res.json({
        success: true
    });
});

// =====================================================
// DATABASE TABLES
// =====================================================

const ALLOWED_TABLES = new Set([
    "exam_schedules",
    "fee_payments",
    "institution_courses",
    "institution_notices",
    "institution_sections",
    "institution_semesters",
    "student_attendance",
    "student_progress",
    "students"
]);

// =====================================================
// FILTERS
// =====================================================

function applyFilters(query, filters) {
    for (
        const filter of Array.isArray(filters)
            ? filters
            : []
    ) {
        if (!filter?.column) continue;

        const column = String(filter.column);
        const value = filter.value;

        switch (filter.operator || "eq") {
            case "eq":
                query = query.eq(column, value);
                break;

            case "neq":
                query = query.neq(column, value);
                break;

            case "ilike":
                query = query.ilike(column, value);
                break;

            case "in":
                query = query.in(
                    column,
                    Array.isArray(value) ? value : []
                );
                break;

            case "gt":
                query = query.gt(column, value);
                break;

            case "gte":
                query = query.gte(column, value);
                break;

            case "lt":
                query = query.lt(column, value);
                break;

            case "lte":
                query = query.lte(column, value);
                break;

            case "is":
                query = query.is(column, value);
                break;

            default:
                throw new Error(
                    "Unsupported filter operator."
                );
        }
    }

    return query;
}

// =====================================================
// DATABASE API
// =====================================================

app.post("/api/db", async (req, res) => {
    try {
        if (!supabase) {
            return res.status(503).json({
                data: null,
                error: {
                    message:
                        "Supabase is not configured."
                }
            });
        }

        const session = getSession(req);

        if (!session) {
            return res.status(401).json({
                data: null,
                error: {
                    message:
                        "Session expired. Please login again."
                }
            });
        }

        const {
            table,
            operation = "select",
            columns = "*",
            payload,
            options = {},
            filters = [],
            ordering = [],
            limit,
            or,
            selectAfterWrite
        } = req.body || {};

        if (!ALLOWED_TABLES.has(table)) {
            return res.status(400).json({
                data: null,
                error: {
                    message: "Table is not allowed."
                }
            });
        }

        const allowedOperations = [
            "select",
            "insert",
            "update",
            "delete",
            "upsert"
        ];

        if (!allowedOperations.includes(operation)) {
            return res.status(400).json({
                data: null,
                error: {
                    message:
                        "Unsupported database operation."
                }
            });
        }

        const institutionId =
            session.institutionId;

        let query;

        // Force institution ID on writes.
        function scopedPayload(input) {
            if (Array.isArray(input)) {
                return input.map(row => ({
                    ...row,
                    institution_id: institutionId
                }));
            }

            return {
                ...(input || {}),
                institution_id: institutionId
            };
        }

        switch (operation) {
            case "select":
                query = supabase
                    .from(table)
                    .select(columns || "*");
                break;

            case "insert":
                query = supabase
                    .from(table)
                    .insert(scopedPayload(payload));
                break;

            case "update": {
                const updatePayload = {
                    ...(payload || {})
                };

                // Client cannot move a row
                // to another institution.
                delete updatePayload.institution_id;

                query = supabase
                    .from(table)
                    .update(updatePayload);

                break;
            }

            case "delete":
                query = supabase
                    .from(table)
                    .delete();
                break;

            case "upsert":
                query = supabase
                    .from(table)
                    .upsert(
                        scopedPayload(payload),
                        options || {}
                    );
                break;
        }

        if (
            operation !== "select" &&
            selectAfterWrite
        ) {
            query = query.select(
                columns || "*"
            );
        }

        // Restrict every operation to
        // the logged-in institution.
        query = query.eq(
            "institution_id",
            institutionId
        );

        query = applyFilters(
            query,
            filters
        );

        if (or) {
            query = query.or(String(or));
        }

        for (
            const item of Array.isArray(ordering)
                ? ordering
                : []
        ) {
            if (!item?.column) continue;

            query = query.order(
                String(item.column),
                {
                    ascending:
                        item.ascending !== false,
                    nullsFirst:
                        item.nullsFirst,
                    referencedTable:
                        item.referencedTable
                }
            );
        }

        if (
            limit !== null &&
            limit !== undefined &&
            Number.isFinite(Number(limit))
        ) {
            query = query.limit(
                Math.max(0, Number(limit))
            );
        }

        const result = await query;

        return res
            .status(result.error ? 400 : 200)
            .json({
                data: result.data ?? null,
                error: result.error
                    ? {
                        message:
                            result.error.message,
                        details:
                            result.error.details,
                        hint:
                            result.error.hint,
                        code:
                            result.error.code
                    }
                    : null
            });

    } catch (error) {
        console.error(
            "DATABASE ERROR:",
            error.message
        );

        return res.status(500).json({
            data: null,
            error: {
                message:
                    "Database request failed. Check Render logs."
            }
        });
    }
});

// =====================================================
// UNKNOWN API ROUTES — RETURN JSON, NOT HTML
// =====================================================

app.use("/api", (req, res) => {
    res.status(404).json({
        success: false,
        message:
            "API route not found: " +
            req.method +
            " " +
            req.originalUrl
    });
});

// =====================================================
// HTML + STATIC FILES
// =====================================================

// Serve main page before static middleware.
app.get("/", (req, res) => {
    res.sendFile(
        path.join(
            __dirname,
            "institution-access-render-fixed.html"
        )
    );
});

app.use(express.static(__dirname));

// =====================================================
// START RENDER SERVER
// =====================================================

app.listen(PORT, "0.0.0.0", () => {
    console.log(
        "Institution Access running on port " +
        PORT
    );
});
