/**
 * Created by Lucas Teske on 30/06/17.
 * @flow
 */

const exec = require('child_process').exec;

const keyToSign = '870AFA59';

const reg = /-----BEGIN PGP SIGNATURE-----([^]*)-----END PGP SIGNATURE-----/;

async function getFingerPrint() {
  return new Promise((resolve, reject) => {
    const child = exec(`gpg --list-keys --with-colons --fingerprint ${keyToSign} |grep pub`, (error, stdout, stderr) => {
      if (error) {
        console.log(`Error signign data (${error}): ${stderr}`);
        reject(error);
      } else {
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

export default async function (body) {
  const fingerPrint = await getFingerPrint();
  return new Promise((resolve, reject) => {
    const child = exec(`gpg -u ${keyToSign} --clearsign`, (error, stdout, stderr) => {
      if (error) {
        console.log(`Error signign data (${error}): ${stderr}`);
        reject(error);
      } else {
        // Grab only the signature hash
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
          resolve({
            signature,
            fingerPrint,
          });
        } else {
          reject('cannot find signature on stdout');
        }
      }
    });

    child.stdin.setEncoding('utf-8');
    child.stdin.write(body);
    child.stdin.end();
  });
}
