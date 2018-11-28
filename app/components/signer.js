/**
 * Created by Lucas Teske on 30/06/17.
 * @flow
 */

const exec = require('child_process').exec;

const keyToSign = null;

const reg = /-----BEGIN PGP SIGNATURE-----([^]*)-----END PGP SIGNATURE-----/;
const hashReg = /Hash: (.*)/;

async function getFingerPrint(gpgKey) {
  const k = gpgKey === undefined || gpgKey === null ? keyToSign : gpgKey;
  if (k === null) {
  	return null;
  }
  return new Promise((resolve, reject) => {
    const child = exec(`gpg2 --list-keys --with-colons --batch --fingerprint ${k} |grep pub`, (error, stdout, stderr) => {
      if (error) {
        console.log(`Error getting fingerprint (${error}): ${stderr}`);
        reject(error);
      } else {
        console.log(`gpg2 --list-keys --with-colons --batch --fingerprint ${k} |grep pub output:\n${stdout}`);
        const s = stdout.split(':');
        if (s.length > 4) {
          resolve(s[4].trim());
        } else {
          reject('unknown');
        }
      }
    })
  })
}

async function _sign(body, gpgKey) {
  const fingerPrint = await getFingerPrint(gpgKey);
  if (fingerPrint === null) {
	return "";
  }
  return new Promise((resolve, reject) => {
    const child = exec(`gpg2 -u ${fingerPrint} --batch --digest-algo SHA512 --clearsign`, (error, stdout, stderr) => {
      if (error) {
        console.log(`Error signign data (${error}): ${stderr}`);
        reject(error);
      } else {
        console.log(`gpg2 -u ${fingerPrint} --clearsign output:\n${stdout}`);
        // Grab only the signature hash
        const hash = stdout.match(hashReg);
        const rm = stdout.match(reg);
        if (rm.length === 2) {
          const z = rm[1].trim().split('\n');
          let signature = '';
          let save = false;
          z.forEach((l) => {
            if (!save) {
              if (l.length === 0) {
                save = true;
              }
            } else {
              signature += l;
            }
          });
          if (!save) {
            signature = z.join(''); // MacOSX Case
          }
          resolve({
            signature,
            fingerPrint,
            hash: hash[1],
          });
        } else {
          console.log('Error: Cannot find signature in stdout!');
          reject('cannot find signature on stdout');
        }
      }
    });

    child.stdin.setEncoding('utf-8');
    child.stdin.write(body);
    child.stdin.end();
  });
}

async function _getKeyName(fingerPrint) {
  return new Promise((resolve, reject) => {
    const child = exec(`gpg2 --list-secret-keys --with-colon "${fingerPrint}" | grep uid`, (error, stdout, stderr) => {
      if (error) {
        console.log(`Error getting list of keys (${error}): ${stderr}`);
        reject(error);
      } else {
        console.log(`gpg2 --list-secret-keys --with-colon "${fingerPrint}" | grep uid output:\n${stdout}`);
        const keysS = stdout.trim().split(':');
        if (keysS.length > 9) {
          return resolve(keysS[9]);
        }
        return resolve('Unknown');
      }
    })
  });
}

async function _getAvailableKeys() {
  return new Promise((resolve, reject) => {
    const child = exec('gpg2 --list-secret-keys --with-colon |grep sec', (error, stdout, stderr) => {
      if (error) {
        console.log(`Error getting list of keys (${error}): ${stderr}`);
        reject(error);
      } else {
        console.log(`gpg2 --list-secret-keys --with-colon |grep sec output:\n${stdout}`);
        const keysS = stdout.trim().split('\n');
        const keys = [];
        keysS.forEach((k) => {
          const s = k.split(':');
          if (s.length > 9) {
            keys.push({
              fingerPrint: s[4],
              name: 'Unknown',
            })
          }
        });
        resolve(keys);
      }
    })
  });
}

export async function getAvailableKeys() {
  const keys = await _getAvailableKeys();

  for (let i = 0; i < keys.length; i++) {
    keys[i].name = await _getKeyName(keys[i].fingerPrint);
  }

  return keys;
}

export async function sign(body, gpgKey) {
  return _sign(body.trim(), gpgKey === undefined || gpgKey === null ? keyToSign : gpgKey);
}
