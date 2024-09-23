import crypto from 'crypto';
function generateSalt(length: number): string {
    return crypto.randomBytes(length).toString('hex')
}

function hash (password: string, salt: string): string {
    const hash = crypto.createHash('sha256')
    hash.update(password + salt)
    return salt + ':' + hash.digest('hex')
}

function compare(password: string, hashed: string): boolean {
    const [salt, originalHash]: string[] = hashed.split(':');
    const hash = crypto.createHash('sha256');
    hash.update(password + salt);
    const newHash = hash.digest('hex')
    return newHash === originalHash
}

const hashedPassword = hash('samer99yousry', generateSalt(16))
console.log(compare('samer99yousry', hashedPassword))
