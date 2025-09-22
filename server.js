const express = require('express');
const app = express();

// Telnyx posts JSON (set the raw/body parser as needed for signature verification later)
app.use(express.json());

app.get('/', (req, res) => {
  res.send('Telnyx Webhook up');
});

app.post('/webhook', (req, res) => {
  console.log('Webhook received:', JSON.stringify(req.body));
  // TODO: verify Telnyx signature with your signing secret before trusting the payload
  res.status(200).send('ok');
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`listening on :${port}`));
