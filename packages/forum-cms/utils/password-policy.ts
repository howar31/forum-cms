const PASSWORD_MAX_AGE_DAYS = 184;
const PASSWORD_MAX_AGE_MS = PASSWORD_MAX_AGE_DAYS * 24 * 60 * 60 * 1000;
const PASSWORD_MIN_LENGTH = 13;
const LETTER_REGEX = /[A-Za-z]/;
const DIGIT_REGEX = /\d/;
const SPECIAL_CHAR_REGEX = /[^A-Za-z0-9]/;
const PASSWORD_REQUIREMENT_MESSAGE =
    "密碼需至少 13 個字元，並包含英文字母、數字與特殊符號";

type PasswordPolicySubject = {
    passwordUpdatedAt?: string | Date | null;
    mustChangePassword?: boolean | null;
};

function getTimestamp(value?: string | Date | null) {
    if (!value) {
        return undefined;
    }

    if (value instanceof Date && !Number.isNaN(value.getTime())) {
        return value.getTime();
    }

    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) {
        return undefined;
    }

    return parsed.getTime();
}

export function isPasswordExpired(subject?: PasswordPolicySubject | null) {
    if (!subject) {
        return true;
    }

    if (subject.mustChangePassword) {
        return true;
    }

    const timestamp = getTimestamp(subject.passwordUpdatedAt);
    if (!timestamp) {
        return true;
    }

    const age = Date.now() - timestamp;
    return age >= PASSWORD_MAX_AGE_MS;
}

export function isPasswordValid(subject?: PasswordPolicySubject | null) {
    return !isPasswordExpired(subject);
}

export function shouldForcePasswordChange(session?: {
    data?: PasswordPolicySubject | null;
}) {
    return isPasswordExpired(session?.data);
}

export function assertPasswordStrength(password: string) {
    if (typeof password !== "string") {
        throw new Error(PASSWORD_REQUIREMENT_MESSAGE);
    }
    const value = password.trim();
    if (
        value.length < PASSWORD_MIN_LENGTH ||
        !LETTER_REGEX.test(value) ||
        !DIGIT_REGEX.test(value) ||
        !SPECIAL_CHAR_REGEX.test(value)
    ) {
        throw new Error(PASSWORD_REQUIREMENT_MESSAGE);
    }
}

/**
 * Check if a password matches any password in the history
 * @param password - Plain text password to check
 * @param passwordHistory - Array of bcrypt hashes from password history
 * @returns Promise<boolean> - true if password matches any history entry
 */
export async function checkPasswordHistory(
    password: string,
    passwordHistory: string[] | null | undefined
): Promise<boolean> {
    if (
        !passwordHistory ||
        !Array.isArray(passwordHistory) ||
        passwordHistory.length === 0
    ) {
        return false;
    }

    const bcrypt = await import("bcryptjs");

    // Check against all history entries
    for (let i = 0; i < passwordHistory.length; i++) {
        const hash = passwordHistory[i];
        if (typeof hash === "string" && hash.length > 0) {
            try {
                const matches = await bcrypt.compare(password, hash);
                if (matches) {
                    return true;
                }
            } catch (error) {
                // If comparison fails, continue checking other entries
                console.error("Error comparing password with history:", error);
            }
        }
    }

    return false;
}

/**
 * Add current password hash to history, keeping only the last 2 entries
 * This ensures we check: current password + 2 history entries = 3 total checks
 * @param currentPasswordHash - Current password bcrypt hash
 * @param passwordHistory - Existing password history array
 * @returns Updated password history array (max 2 entries)
 */
export function addToPasswordHistory(
    currentPasswordHash: string,
    passwordHistory: string[] | null | undefined
): string[] {
    const history = Array.isArray(passwordHistory) ? [...passwordHistory] : [];

    // Add current hash to the beginning
    history.unshift(currentPasswordHash);

    // Keep only the last 2 entries (current password is checked separately)
    return history.slice(0, 2);
}

export const passwordPolicy = {
    maxAgeDays: PASSWORD_MAX_AGE_DAYS,
    maxAgeMs: PASSWORD_MAX_AGE_MS,
    minLength: PASSWORD_MIN_LENGTH,
    requirementsMessage: PASSWORD_REQUIREMENT_MESSAGE,
    isPasswordExpired,
    isPasswordValid,
    shouldForcePasswordChange,
    assertPasswordStrength,
    checkPasswordHistory,
    addToPasswordHistory,
};
