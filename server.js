const express = require("express");
const path = require("path");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

const app = express();

const PORT = process.env.PORT || 10000;

/* =========================================================
   MIDDLEWARE
========================================================= */

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

/* =========================================================
   SUPABASE
   KEYS COME ONLY FROM RENDER ENVIRONMENT VARIABLES
========================================================= */

const SUPABASE_URL =
    process.env.SUPABASE_URL || "";

const SUPABASE_KEY =
    process.env.SUPABASE_SECRET_KEY ||
    process.env.SUPABASE_SERVICE_ROLE_KEY ||
    process.env.SUPABASE_ANON_KEY ||
    "";

const SESSION_SECRET =
    process.env.SESSION_SECRET ||
    crypto.randomBytes(32).toString("hex");

if (!SUPABASE_URL || !SUPABASE_KEY) {
    console.error(
        "ERROR: SUPABASE_URL or SUPABASE_SECRET_KEY is missing."
    );
}

const supabase = createClient(
    SUPABASE_URL,
    SUPABASE_KEY,
    {
        auth: {
            autoRefreshToken: false,
            persistSession: false
        }
    }
);

/* =========================================================
   SESSION FUNCTIONS
========================================================= */

function sign(value) {

    return crypto
        .createHmac(
            "sha256",
            SESSION_SECRET
        )
        .update(value)
        .digest("base64url");

}


function makeSession(institutionId) {

    const payload = Buffer
        .from(
            JSON.stringify({
                institutionId: String(institutionId),
                exp:
                    Date.now() +
                    (12 * 60 * 60 * 1000)
            })
        )
        .toString("base64url");

    return (
        payload +
        "." +
        sign(payload)
    );

}


/* =========================================================
   COOKIE FUNCTIONS
========================================================= */

function readCookies(req) {

    const raw =
        req.headers.cookie || "";

    const cookies = {};

    raw
        .split(";")
        .forEach(part => {

            const index =
                part.indexOf("=");

            if (index === -1) return;

            const key =
                part
                    .slice(0, index)
                    .trim();

            const value =
                part
                    .slice(index + 1)
                    .trim();

            if (key) {
                cookies[key] =
                    decodeURIComponent(value);
            }

        });

    return cookies;

}


function getSession(req) {

    const cookies =
        readCookies(req);

    const token =
        cookies.institution_session;

    if (!token) {
        return null;
    }

    const parts =
        token.split(".");

    if (parts.length !== 2) {
        return null;
    }

    const payload =
        parts[0];

    const signature =
        parts[1];

    const expected =
        sign(payload);

    if (
        signature.length !==
        expected.length
    ) {
        return null;
    }

    if (
        !crypto.timingSafeEqual(
            Buffer.from(signature),
            Buffer.from(expected)
        )
    ) {
        return null;
    }

    try {

        const data =
            JSON.parse(
                Buffer
                    .from(
                        payload,
                        "base64url"
                    )
                    .toString("utf8")
            );

        if (
            !data.institutionId ||
            Number(data.exp) < Date.now()
        ) {
            return null;
        }

        return data;

    } catch {

        return null;

    }

}


/* =========================================================
   SET SESSION COOKIE
========================================================= */

function setSessionCookie(
    req,
    res,
    institutionId
) {

    const secure =
        req.headers["x-forwarded-proto"] ===
        "https" ||
        req.secure;

    const token =
        makeSession(
            institutionId
        );

    res.setHeader(
        "Set-Cookie",
        [
            "institution_session=" +
                encodeURIComponent(token),

            "Path=/",

            "HttpOnly",

            "SameSite=Lax",

            secure
                ? "Secure"
                : ""
        ]
        .filter(Boolean)
        .join("; ")
    );

}


/* =========================================================
   CLEAR SESSION
========================================================= */

function clearSessionCookie(
    req,
    res
) {

    const secure =
        req.headers["x-forwarded-proto"] ===
        "https" ||
        req.secure;

    res.setHeader(
        "Set-Cookie",
        [
            "institution_session=",

            "Path=/",

            "HttpOnly",

            "SameSite=Lax",

            "Max-Age=0",

            secure
                ? "Secure"
                : ""
        ]
        .filter(Boolean)
        .join("; ")
    );

}


/* =========================================================
   LOGIN
========================================================= */

app.post(
    "/api/login",
    async (req, res) => {

        try {

            const loginId =
                String(
                    req.body?.loginId || ""
                ).trim();

            const password =
                String(
                    req.body?.password || ""
                ).trim();

            if (
                !loginId ||
                !password
            ) {

                return res
                    .status(400)
                    .json({
                        success: false,
                        message:
                            "Please enter login ID and password."
                    });

            }

            const upperId =
                loginId.toUpperCase();

            const {
                data,
                error
            } =
                await supabase
                    .from("institutions")
                    .select("*")
                    .or(
                        "email.eq." +
                        loginId +
                        ",institution_id.eq." +
                        upperId
                    )
                    .eq(
                        "status",
                        "active"
                    )
                    .limit(1);

            if (error) {
                throw error;
            }

            if (
                !data ||
                !data.length
            ) {

                return res
                    .status(401)
                    .json({
                        success: false,
                        message:
                            "Institution account not found."
                    });

            }

            const row =
                data[0];

            if (
                String(
                    row.access_password || ""
                ) !== password
            ) {

                return res
                    .status(401)
                    .json({
                        success: false,
                        message:
                            "Invalid login details."
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

                    institution_id:
                        row.institution_id,

                    institution_type:
                        row.institution_type,

                    institution_name:
                        row.institution_name,

                    branches:
                        row.branches,

                    mobile:
                        row.mobile,

                    email:
                        row.email,

                    address:
                        row.address,

                    logo_url:
                        row.logo_url

                }

            });

        } catch (error) {

            console.error(
                "LOGIN ERROR:",
                error
            );

            return res
                .status(500)
                .json({

                    success: false,

                    message:
                        error?.message ||
                        "Login failed."

                });

        }

    }
);


/* =========================================================
   LOGOUT
========================================================= */

app.post(
    "/api/logout",
    (req, res) => {

        clearSessionCookie(
            req,
            res
        );

        res.json({
            success: true
        });

    }
);


/* =========================================================
   ALLOWED DATABASE TABLES
========================================================= */

const ALLOWED_TABLES =
    new Set([

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


/* =========================================================
   FILTER FUNCTION
========================================================= */

function applyFilters(
    query,
    filters
) {

    for (
        const filter
        of Array.isArray(filters)
            ? filters
            : []
    ) {

        if (
            !filter ||
            !filter.column
        ) {
            continue;
        }

        const column =
            String(
                filter.column
            );

        const operator =
            String(
                filter.operator ||
                "eq"
            );

        const value =
            filter.value;

        switch (operator) {

            case "eq":

                query =
                    query.eq(
                        column,
                        value
                    );

                break;


            case "neq":

                query =
                    query.neq(
                        column,
                        value
                    );

                break;


            case "ilike":

                query =
                    query.ilike(
                        column,
                        value
                    );

                break;


            case "in":

                query =
                    query.in(
                        column,
                        Array.isArray(value)
                            ? value
                            : []
                    );

                break;


            case "gt":

                query =
                    query.gt(
                        column,
                        value
                    );

                break;


            case "gte":

                query =
                    query.gte(
                        column,
                        value
                    );

                break;


            case "lt":

                query =
                    query.lt(
                        column,
                        value
                    );

                break;


            case "lte":

                query =
                    query.lte(
                        column,
                        value
                    );

                break;


            case "is":

                query =
                    query.is(
                        column,
                        value
                    );

                break;


            default:

                throw new Error(
                    "Unsupported filter operator: " +
                    operator
                );

        }

    }

    return query;

}


/* =========================================================
   DATABASE API
========================================================= */

app.post(
    "/api/db",
    async (req, res) => {

        try {

            const session =
                getSession(req);

            if (!session) {

                return res
                    .status(401)
                    .json({

                        data: null,

                        error: {
                            message:
                                "Session expired. Please login again."
                        }

                    });

            }

            const {

                table,

                operation =
                    "select",

                columns =
                    "*",

                payload,

                options = {},

                filters = [],

                ordering = [],

                limit,

                or,

                selectAfterWrite

            } = req.body || {};


            if (
                !ALLOWED_TABLES.has(
                    table
                )
            ) {

                return res
                    .status(400)
                    .json({

                        data: null,

                        error: {
                            message:
                                "Table is not allowed."
                        }

                    });

            }


            if (
                ![
                    "select",
                    "insert",
                    "update",
                    "delete",
                    "upsert"
                ].includes(
                    operation
                )
            ) {

                return res
                    .status(400)
                    .json({

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


            /* SELECT */

            if (
                operation ===
                "select"
            ) {

                query =
                    supabase
                        .from(table)
                        .select(
                            columns || "*"
                        );

            }


            /* INSERT */

            if (
                operation ===
                "insert"
            ) {

                let insertPayload =
                    payload;

                if (
                    Array.isArray(
                        insertPayload
                    )
                ) {

                    insertPayload =
                        insertPayload.map(
                            row => ({
                                ...row,
                                institution_id:
                                    institutionId
                            })
                        );

                } else {

                    insertPayload = {
                        ...(insertPayload || {}),
                        institution_id:
                            institutionId
                    };

                }


                query =
                    supabase
                        .from(table)
                        .insert(
                            insertPayload
                        );

                if (
                    selectAfterWrite
                ) {

                    query =
                        query.select(
                            columns || "*"
                        );

                }

            }


            /* UPDATE */

            if (
                operation ===
                "update"
            ) {

                query =
                    supabase
                        .from(table)
                        .update(
                            payload || {}
                        );

                if (
                    selectAfterWrite
                ) {

                    query =
                        query.select(
                            columns || "*"
                        );

                }

            }


            /* DELETE */

            if (
                operation ===
                "delete"
            ) {

                query =
                    supabase
                        .from(table)
                        .delete();

                if (
                    selectAfterWrite
                ) {

                    query =
                        query.select(
                            columns || "*"
                        );

                }

            }


            /* UPSERT */

            if (
                operation ===
                "upsert"
            ) {

                let upsertPayload =
                    payload;

                if (
                    Array.isArray(
                        upsertPayload
                    )
                ) {

                    upsertPayload =
                        upsertPayload.map(
                            row => ({
                                ...row,
                                institution_id:
                                    institutionId
                            })
                        );

                } else {

                    upsertPayload = {
                        ...(upsertPayload || {}),
                        institution_id:
                            institutionId
                    };

                }


                query =
                    supabase
                        .from(table)
                        .upsert(
                            upsertPayload,
                            options || {}
                        );

                if (
                    selectAfterWrite
                ) {

                    query =
                        query.select(
                            columns || "*"
                        );

                }

            }


            /*
              Always restrict records
              to current institution.
            */

            query =
                query.eq(
                    "institution_id",
                    institutionId
                );


            /*
              Apply HTML filters.
            */

            query =
                applyFilters(
                    query,
                    filters
                );


            /* OR FILTER */

            if (or) {

                query =
                    query.or(
                        String(or)
                    );

            }


            /* ORDER */

            for (
                const item
                of Array.isArray(ordering)
                    ? ordering
                    : []
            ) {

                if (
                    !item?.column
                ) {
                    continue;
                }

                query =
                    query.order(
                        String(
                            item.column
                        ),
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


            /* LIMIT */

            if (
                limit !== null &&
                limit !== undefined &&
                Number.isFinite(
                    Number(limit)
                )
            ) {

                query =
                    query.limit(
                        Number(limit)
                    );

            }


            const result =
                await query;


            return res
                .status(
                    result.error
                        ? 400
                        : 200
                )
                .json({

                    data:
                        result.data ??
                        null,

                    error:
                        result.error
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
                error
            );

            return res
                .status(500)
                .json({

                    data: null,

                    error: {
                        message:
                            error?.message ||
                            "Database request failed."
                    }

                });

        }

    }
);


/* =========================================================
   HEALTH CHECK
========================================================= */

app.get(
    "/api/health",
    (req, res) => {

        res.json({

            success: true,

            server:
                "Institution Access",

            databaseConfigured:
                Boolean(
                    SUPABASE_URL &&
                    SUPABASE_KEY
                )

        });

    }
);


/* =========================================================
   UNKNOWN API ROUTES
========================================================= */

app.use(
    "/api",
    (req, res) => {

        res
            .status(404)
            .json({

                success: false,

                message:
                    "API route not found: " +
                    req.method +
                    " " +
                    req.path

            });

    }
);


/* =========================================================
   STATIC FILES
========================================================= */

app.use(
    express.static(__dirname)
);


/* =========================================================
   MAIN HTML
========================================================= */

app.get(
    "/",
    (req, res) => {

        res.sendFile(
            path.join(
                __dirname,
                "institution-access-render.html"
            )
        );

    }
);


/* =========================================================
   START SERVER
========================================================= */

app.listen(
    PORT,
    "0.0.0.0",
    () => {

        console.log(
            "Institution Access running on port " +
            PORT
        );

    }
);
