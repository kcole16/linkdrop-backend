const Koa = require('koa');
const app = new Koa();

const body = require('koa-json-body');
const cors = require('@koa/cors');
const httpErrors = require('http-errors');

app.use(require('koa-logger')());
app.use(body({ limit: '500kb', fallback: true }));
app.use(cors({ credentials: true }));

// Middleware to passthrough HTTP errors from node
app.use(async function(ctx, next) {
    try {
        await next();
    } catch(e) {
        if (e.response) {
            ctx.throw(e.response.status, e.response.text);
        }

        if (e instanceof httpErrors.Forbidden) {
            ctx.throw(e);
        }

        // TODO: Figure out which errors should be exposed to user
        console.error('Error: ', e, JSON.stringify(e));
        ctx.throw(400, e.toString());
    }
});

const Router = require('koa-router');
const router = new Router();

const creatorKeyJson = JSON.parse(process.env.ACCOUNT_CREATOR_KEY);
const recoveryKeyJson = JSON.parse(process.env.ACCOUNT_RECOVERY_KEY);
const keyStore = {
    async getKey(networkId, accountId) {
        if (accountId == creatorKeyJson.account_id) {
            return KeyPair.fromString(creatorKeyJson.private_key);
        }
        // For account recovery purposes use recovery key when updating any account
        return KeyPair.fromString(recoveryKeyJson.private_key);
    }
};
const { connect, KeyPair } = require('nearlib');
const nearPromise = (async () => {
    const near = await connect({
        deps: { keyStore },
        masterAccount: creatorKeyJson.account_id,
        nodeUrl: process.env.NODE_URL
    });
    return near;
})();
app.use(async (ctx, next) => {
    ctx.near = await nearPromise;
    await next();
});

// router.post('/account', async ctx => {
//     const { newAccountId, newAccountPublicKey } = ctx.request.body;
//     const masterAccount = await ctx.near.account(creatorKeyJson.account_id);
//     ctx.body = await masterAccount.createAccount(newAccountId, newAccountPublicKey, NEW_ACCOUNT_AMOUNT);
// });

const LINKDROP_CONTRACT_ID = 'linkdrop-test-1';
const BOATLOAD_OF_GAS = '10000000000000000';

router.get('/', async ctx => {
    // Generate temp keypair
    const keypair = KeyPair.fromRandom('ed25519'); 

    const masterAccount = await ctx.near.account(creatorKeyJson.account_id);

    // Create TX to send to linkdrop contract
    console.log(keypair.publicKey.toString().split(':')[1])
    const contract = await ctx.near.loadContract(LINKDROP_CONTRACT_ID, {
        viewMethods: [],
        changeMethods: ['send', 'claim', 'create_account_and_claim'],
        sender: creatorKeyJson.account_id
    });
    const result = await contract.send({public_key: keypair.publicKey.toString().split(':')[1]}, BOATLOAD_OF_GAS);
    ctx.body = {"fundingKey": keypair.secretKey.toString()}
});


const nacl = require('tweetnacl');
const crypto = require('crypto');
const bs58 = require('bs58');
const verifySignature = async (nearAccount, securityCode, signature) => {
    const hasher = crypto.createHash('sha256');
    hasher.update(securityCode);
    const hash = hasher.digest();
    const helperPublicKey = (await keyStore.getKey(recoveryKeyJson.account_id)).publicKey;
    const accessKeys = await nearAccount.getAccessKeys();
    if (!accessKeys.find(it => it.public_key == helperPublicKey.toString())) {
        throw Error(`Account ${nearAccount.accountId} doesn't have helper key`);
    }
    return accessKeys.some(it => {
        const publicKey = it.public_key.replace('ed25519:', '');
        return nacl.sign.detached.verify(hash, Buffer.from(signature, 'base64'), bs58.decode(publicKey));
    });
};

app
    .use(router.routes())
    .use(router.allowedMethods());

if (!module.parent) {
    app.listen(3000);
} else {
    module.exports = app;
}
