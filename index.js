const {Ed25519KeyPair, jsonld, util, Buffer, jsYaml} = rdfsig;
const $ = document.querySelectorAll.bind(document);
const DefaultManifest = ['examples/toy.yaml'];

const SearchParms = parseQueryString(window.location.search);
console.log(`Page loaded at ${new Date().toISOString()} with search parms:\n${JSON.stringify(SearchParms, null, 2)}`);

// Paint example buttons.
$('#signGraph')[0].value = ''; // clear out for error messages
(SearchParms.manifestURL || DefaultManifest).forEach(async (m) => {
  let verb = 'load';
  try {
    const resp = await fetch(m);
    if (!resp.ok)
      throw Error(`fetch ${m} returned ${resp.status} ${resp.statusText}`);
    const text = await resp.text();
    verb = 'parse';
    const manifest = m.endsWith('.yaml')
          ? jsYaml.load(text)
          : JSON.parse(text);
    Object.keys(manifest).forEach(label => {
      const elt = document.createElement('button');
      elt.innerText = label
      elt.onclick = () => fill(manifest[label]);
      $('#manifest')[0].appendChild(elt);
    })
  } catch (e) {
    $('#signGraph')[0].value += `Failed to ${verb} ${m}: ${e.message}\n`;
  }
})

// Example button action.
function fill (fields) {
  Object.keys(fields).forEach(
    id => $('#' + id)[0].value = fields[id]
  )
}

// When sign is clicked...
$('#sign')[0].onclick = async function (evt) {
  debugger; // so folks can follow along

  try {
    // Grab parms from form.
    const vals = (['signGraph', 'signNode', 'withProof', 'proofNode', 'privKey']).reduce((acc, key) => {
      acc[key] = $('#' + key)[0].value;
      return acc;
    }, {});
    const f = graphy.core.data.factory;
    const [signGraph, withProof] = await Promise.all([
      parse('ttl', vals.signGraph),
      parse('ttl', vals.withProof),
    ]);
    const signNode = f.namedNode(vals.signNode);
    const proofNode = f.namedNode(vals.proofNode);

    // Copy embeddeed proof with BlankNode subject.
    const embeddedProofNode = f.blankNode();
    const anonymousProof = graphy.memory.dataset.fast();
    ([...withProof.data.quads(null, null, null, null)]).map(q => {
      if (q.subject.equals(proofNode))
        q.subject = embeddedProofNode;
      if (q.object.equals(proofNode))
        q.object = embeddedProofNode;
      anonymousProof.add(q);
    });

    // Construct signing (private) key.
    const keyPair1priv = await Ed25519KeyPair.generate({
      privateKeyBase58: vals.privKey,
    });

    // Compose signature applies to concatonation of both graphs.
    const verifyData = await urdnaizeDocs([
      await write('nt', [...anonymousProof.quads()]),
      await write('nt', [...signGraph.data.quads()]),
    ]);
    const jws = await createJWS(verifyData, keyPair1priv.signer());

    // Add jws token to proof.
    anonymousProof.add(f.quad(
      embeddedProofNode,
      f.namedNode('https://w3id.org/security#jws'), // sec:jws
      f.literal(jws)
    ));

    // Connect proof to signed node.
    signGraph.data.add(f.quad(
      signNode,
      f.namedNode('https://w3id.org/security#proof'), // sec:proof
      embeddedProofNode
    ));

    // Write composite graph to UI.
    signGraph.data.addAll(anonymousProof.quads());
    const text = await write('ttl', [...signGraph.data], {
      prefixes: Object.assign({}, {
        cred: 'https://www.w3.org/2018/credentials#',
        rdf: 'http://www.w3.org/1999/02/22-rdf-syntax-ns#',
      }, signGraph.prefixes, withProof.prefixes)
    });
    $('#signed')[0].value = text;
  } catch (e) {
    $('#signed')[0].value = 'Error: ' + (typeof e === 'object' ? 'message' in e ? e.message : JSON.stringify(e) : e)
  }
}

$('#copyDown')[0].onclick = function (evt) {
  $('#verifyMe')[0].value = $('#signed')[0].value;
}

// When verify is clicked...
$('#verify')[0].onclick = async function (evt) {
  debugger; // so folks can follow along

  try {
    // Grab parms from form.
    const vals = (['verifyMe', 'pubKey', 'keyId']).reduce((acc, key) => {
      acc[key] = $('#' + key)[0].value;
      return acc;
    }, {});
    const f = graphy.core.data.factory;
    const verifyGraph = await parse('ttl', vals.verifyMe);

    // Find the quad with predicate sec:proof
    const proofQuad = extract(
      1, {subject: 'NamedNode', object: 'BlankNode'},
      'asserted proof',
      verifyGraph.data,
      null,
      f.namedNode('https://w3id.org/security#proof'), // sec:proof
      null
    )[0];
    const signNode = proofQuad.subject;
    const embeddedProofNode = proofQuad.object;

    // Find the jws token.
    const jws = extract(
      1, {subject: 'BlankNode', object: 'Literal'},
      'jws token',
      verifyGraph.data,
      embeddedProofNode,
      f.namedNode('https://w3id.org/security#jws'), // sec:jws
      null
    )[0].object.value;

    // Extract the proof graph.
    const anonymousProof = graphy.memory.dataset.fast();
    anonymousProof.addAll(extract(
      null, {},
      'proof triples',
      verifyGraph.data,
      embeddedProofNode,
      null,
      null
    ));

    // Construct public key.
    const keyPair1pub = await Ed25519KeyPair.generate({
      id: vals.keyId,
      publicKeyBase58: vals.pubKey,
    });

    // Verify that signature applies to concatonation of both graphs.
    const verifyData = await urdnaizeDocs([
      await write('nt', [...anonymousProof.quads()]),
      await write('nt', [...verifyGraph.data.quads()]),
    ]);
    const verified = await checkJWS(jws, verifyData, keyPair1pub.verifier());
    $('#result')[0].value = verified;
  } catch (e) {
    $('#result')[0].value = e.message;    
  }
}

/** extract matching triples from a graph.
 * @param count: number | null - how many to expect
 * @param types: object - making of triple component to expected type
 * @param label: string - string to embed in throw Errors.
 * @param graph: Dataset (modified) - where to match s, p, o
 * @param s, p, o: Term | null - what to match
 * @returns extracted triples.
 */
function extract (count, types, label, graph, s, p, o) {
  const quads = [...graph.match(s, p, o)];
  if (count !== null && quads.length !== count)
    throw Error(`fail: expected ${count} ${label}; got ${quads.length}`);
  Object.keys(types).forEach(pos => {
    const misTyped = types[pos] ? quads.find(q => q[pos].termType !== types[pos]) : null;
    if (misTyped)
      throw Error(`fail: expected ${label} of type ${types[pos]}; got ${misTyped[pos].termType}`);
  });
  quads.forEach(q => graph.delete(q));
  return quads
}

async function write (format, data, opts) {
  const writer = graphy.content[format].write(opts);
  return new Promise((resolve, reject) => {
    let ret = '';
    writer.on('data', (turtle) => {
      ret += (turtle + '').replace(/\n\n/g, '\n');
    });
    writer.on('error', (error) => {
      reject(error);
    });
    // writer.on('eof', (prefixes) => {
    //   resolve(ret);
    // });
    data.forEach(q => writer.write(q));
    // I am 100% confident this is how I'm supposed to signal the end of input.
    setTimeout(() => resolve(ret), 100); // but seriously, what do I do here?
    // I tried some stuff that didn't work:
    // writer.end();
    // writer.emit('eof');
  });
}

async function parse (format, str) {
  const data = graphy.memory.dataset.fast();
  return new Promise((resolve, reject) => {
    graphy.content[format].read(str, {
      data(y_quad) {
        data.add(y_quad);
      },
      error(error) {
        reject(error);
      },
      eof(prefixes) {
        resolve({data, prefixes});
      },
    });
  });
}

async function createJWS (verifyData, signer) {
  const header = { alg: 'EdDSA', b64: false, crit: ['b64'] };
  const encodedHeader = util.encodeBase64Url(JSON.stringify(header));
  const data = util.createJws({encodedHeader, verifyData});
  const signature = await signer.sign({data});
  const encodedSignature = util.encodeBase64Url(signature);
  return encodedHeader + '..' + encodedSignature;
}

async function checkJWS (jws, copyVerifyData, verifier) {
  const [encodedHeaderCopy, /*payload*/, encodedSignatureCopy] = jws.split('.');
  const headerCopy = JSON.parse(util.decodeBase64UrlToString(encodedHeaderCopy));
  const signatureCopy = util.decodeBase64Url(encodedSignatureCopy);
  const dataCopy = util.createJws({encodedHeader: encodedHeaderCopy, verifyData: copyVerifyData});
  return await verifier.verify({data: dataCopy, signature: signatureCopy});
  // or call native verify(null, Buffer.from(dataCopy.buffer, dataCopy.byteOffset, dataCopy.length), keyPair1pub, signatureCopy)
}

async function urdnaizeDocs (docs) {
  const canons = await Promise.all(docs.map(
    doc => jsonld.canonize(doc, {
      inputFormat: 'application/n-quads',
      algorithm: 'URDNA2015',
      format: 'application/n-quads',
      skipExpansion: false,
    })
  ));
  const bufs = canons.map(c => util.sha256(c));
  const concat = Buffer.concat(bufs.map(
    b => Buffer.from(b.buffer, b.byteOffset, b.length)
  ));
  return new Uint8Array(concat.buffer, concat.byteOffset, concat.length);
}

function parseQueryString (query) {
  if (query[0]==='?') query=query.substr(1); // optional leading '?'
  const map   = {};
  query.replace(/([^&,=]+)=?([^&,]*)(?:[&,]+|$)/g, function(match, key, value) {
    key=decodeURIComponent(key);value=decodeURIComponent(value);
    (map[key] = map[key] || []).push(value);
  });
  return map;
};

