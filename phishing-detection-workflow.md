# AI Phishing Detection & Auto-Quarantine: n8n Workflow Code

Importable n8n workflow (n8n Cloud). Copy the JSON below into a file named `phishing-detection-cloud.json`, then in n8n use **Workflows → Import from File** (or paste it directly onto the canvas with Ctrl+V).

After import, connect your own credentials (nothing secret is stored in this file) and follow the setup steps in the README.

````json
{
  "name": "AI phishing detection & Auto-Quarantine (n8n Cloud)",
  "nodes": [
    {
      "parameters": {
        "content": "## Setup (n8n Cloud)\n1. Credentials (free tiers): Google Gemini, VirusTotal (Header Auth), Slack, Postgres (Supabase), SMTP optional\n2. Slack node: set your channel name\n3. Send Email node: set from/to address\n4. Create table phishing_logs in Supabase SQL Editor\n5. Click Execute workflow: 3 mock emails run through all branches",
        "height": 200,
        "width": 420
      },
      "id": "ec84d72a-e10a-41a5-9183-c58a937f99f6",
      "name": "Setup notes",
      "type": "n8n-nodes-base.stickyNote",
      "typeVersion": 1,
      "position": [
        -60,
        -140
      ]
    },
    {
      "parameters": {},
      "id": "990c533c-54b5-4533-af35-fac148842b8b",
      "name": "When clicking Execute workflow",
      "type": "n8n-nodes-base.manualTrigger",
      "typeVersion": 1,
      "position": [
        0,
        120
      ]
    },
    {
      "parameters": {
        "jsCode": "return [\n  { json: { from: 'security@paypa1-support.com', subject: 'Urgent: verify your account now', text: 'Your account is suspended. Click http://paypa1-secure-login.example.com/verify within 24 hours to restore access.' } },\n  { json: { from: 'ceo.office@company-mail.biz', subject: 'Quick favor, urgent', text: 'Are you at your desk? I need you to buy gift cards for a client today. Reply only to me, do not call.' } },\n  { json: { from: 'newsletter@github.com', subject: 'Your weekly digest', text: 'Here are the repositories trending this week. Thanks for being part of the community.' } }\n];"
      },
      "id": "f00b4c48-8e97-4d57-a27f-4bd237bcd065",
      "name": "Mock Emails",
      "type": "n8n-nodes-base.code",
      "typeVersion": 2,
      "position": [
        220,
        120
      ]
    },
    {
      "parameters": {
        "jsCode": "const out = [];\nfor (const item of $input.all()) {\n  const d = item.json;\n  const f = d.from;\n  let from = '';\n  if (typeof f === 'string') from = f;\n  else if (f) from = f.text || (f.value && f.value[0] && f.value[0].address) || '';\n  const body = String(d.text || d.textPlain || d.html || d.textHtml || '').slice(0, 4000);\n  const urls = [...new Set(body.match(/https?:\\/\\/[^\\s\"'<>)\\]]+/g) || [])];\n  out.push({ json: {\n    from,\n    subject: d.subject || '',\n    body,\n    urls,\n    firstUrl: urls[0] || '',\n    messageId: d.messageId || ''\n  }});\n}\nreturn out;"
      },
      "id": "1a995f28-945c-4e58-89dd-3bbecd29bbcc",
      "name": "Normalize Email",
      "type": "n8n-nodes-base.code",
      "typeVersion": 2,
      "position": [
        440,
        220
      ]
    },
    {
      "parameters": {
        "conditions": {
          "options": {
            "caseSensitive": true,
            "leftValue": "",
            "typeValidation": "strict",
            "version": 2
          },
          "conditions": [
            {
              "id": "66bf071b-9963-4cd2-a3c5-a98968dbb9fc",
              "leftValue": "={{ $json.firstUrl }}",
              "rightValue": "",
              "operator": {
                "type": "string",
                "operation": "notEmpty",
                "singleValue": true
              }
            }
          ],
          "combinator": "and"
        },
        "options": {}
      },
      "id": "6506456a-2dab-4fbe-b251-ff7f558a7db4",
      "name": "Has URL?",
      "type": "n8n-nodes-base.if",
      "typeVersion": 2.2,
      "position": [
        660,
        220
      ]
    },
    {
      "parameters": {
        "authentication": "genericCredentialType",
        "genericAuthType": "httpHeaderAuth",
        "method": "POST",
        "url": "https://www.virustotal.com/api/v3/urls",
        "sendBody": true,
        "contentType": "form-urlencoded",
        "bodyParameters": {
          "parameters": [
            {
              "name": "url",
              "value": "={{ $json.firstUrl }}"
            }
          ]
        },
        "options": {}
      },
      "id": "0aa7e60f-73e2-4505-b86f-d504324605f6",
      "name": "VT Submit URL",
      "type": "n8n-nodes-base.httpRequest",
      "typeVersion": 4.2,
      "position": [
        880,
        120
      ],
      "credentials": {
        "httpHeaderAuth": {
          "id": "REPLACE_VT",
          "name": "VirusTotal Header Auth"
        }
      },
      "onError": "continueRegularOutput"
    },
    {
      "parameters": {
        "amount": 15,
        "unit": "seconds"
      },
      "id": "9e551f1f-d9b4-4247-9cf6-4ddc442b9bcf",
      "name": "Wait 15s",
      "type": "n8n-nodes-base.wait",
      "typeVersion": 1.1,
      "position": [
        1100,
        120
      ],
      "webhookId": "55e0d951-2711-4011-b119-0b4e3b66f723"
    },
    {
      "parameters": {
        "authentication": "genericCredentialType",
        "genericAuthType": "httpHeaderAuth",
        "url": "=https://www.virustotal.com/api/v3/analyses/{{ $json.data.id }}",
        "options": {}
      },
      "id": "da8591a2-eed8-4552-8dd3-7422b55bef1b",
      "name": "VT Get Result",
      "type": "n8n-nodes-base.httpRequest",
      "typeVersion": 4.2,
      "position": [
        1320,
        120
      ],
      "credentials": {
        "httpHeaderAuth": {
          "id": "REPLACE_VT",
          "name": "VirusTotal Header Auth"
        }
      },
      "onError": "continueRegularOutput"
    },
    {
      "parameters": {
        "assignments": {
          "assignments": [
            {
              "id": "420997d2-4198-47e6-ba24-40d6aada5bca",
              "name": "from",
              "value": "={{ $('Normalize Email').item.json.from }}",
              "type": "string"
            },
            {
              "id": "9a90fed4-2a20-476b-833b-07c61ecc032f",
              "name": "subject",
              "value": "={{ $('Normalize Email').item.json.subject }}",
              "type": "string"
            },
            {
              "id": "57c3a5da-f7de-44c9-87f1-6c2de633a05e",
              "name": "body",
              "value": "={{ $('Normalize Email').item.json.body }}",
              "type": "string"
            },
            {
              "id": "95f697e2-a13a-4716-8361-79115e5926fb",
              "name": "firstUrl",
              "value": "={{ $('Normalize Email').item.json.firstUrl }}",
              "type": "string"
            },
            {
              "id": "0ba9e06e-ced2-4242-a8d6-570ba483b8de",
              "name": "messageId",
              "value": "={{ $('Normalize Email').item.json.messageId }}",
              "type": "string"
            },
            {
              "id": "cb0557c8-0ed8-4c17-b3bb-042c6b2a7b00",
              "name": "vt_summary",
              "value": "={{ $json.data && $json.data.attributes && $json.data.attributes.stats ? JSON.stringify($json.data.attributes.stats) : 'no URL scan available' }}",
              "type": "string"
            }
          ]
        },
        "options": {}
      },
      "id": "de471b4f-3d29-42d7-9b0c-26c7eabfdb09",
      "name": "Prep Context",
      "type": "n8n-nodes-base.set",
      "typeVersion": 3.4,
      "position": [
        1540,
        220
      ]
    },
    {
      "parameters": {
        "promptType": "define",
        "hasOutputParser": true,
        "text": "=You are a phishing detection analyst. Classify this email: risk_level low, medium or high (high = clear phishing or malicious VirusTotal detections, medium = suspicious signs, low = looks legitimate), a score 0-100 and a one-sentence reason.\nFrom: {{ $json.from }}\nSubject: {{ $json.subject }}\nLink: {{ $json.firstUrl || 'none' }}\nVirusTotal stats: {{ $json.vt_summary }}\nBody:\n{{ $json.body }}"
      },
      "id": "81770424-6e8e-42a2-b4a4-ae0851f3d651",
      "name": "Analyze Email",
      "type": "@n8n/n8n-nodes-langchain.chainLlm",
      "typeVersion": 1.5,
      "position": [
        1760,
        220
      ],
      "retryOnFail": true,
      "maxTries": 3,
      "waitBetweenTries": 5000
    },
    {
      "parameters": {
        "modelName": "models/gemini-2.5-flash",
        "options": {}
      },
      "id": "2b109fb4-ca27-411e-bda0-ee84402eabc8",
      "name": "Google Gemini Chat Model",
      "type": "@n8n/n8n-nodes-langchain.lmChatGoogleGemini",
      "typeVersion": 1,
      "position": [
        1780,
        440
      ],
      "credentials": {
        "googlePalmApi": {
          "id": "REPLACE_GEMINI",
          "name": "Google Gemini(PaLM) Api account"
        }
      }
    },
    {
      "parameters": {
        "mode": "runOnceForEachItem",
        "jsCode": "const ctx = $('Prep Context').item.json;\nlet r = $json.output;\nif (typeof r === 'string') {\n  try { const m = r.match(/\\{[\\s\\S]*\\}/); r = m ? JSON.parse(m[0]) : {}; } catch (e) { r = {}; }\n}\nr = r || {};\nconst level = String(r.risk_level || 'medium').toLowerCase();\nreturn { json: {\n  from: ctx.from,\n  subject: ctx.subject,\n  messageId: ctx.messageId,\n  vt_summary: ctx.vt_summary,\n  risk_level: ['low', 'medium', 'high'].includes(level) ? level : 'medium',\n  score: Number(r.score) || 50,\n  reason: String(r.reason || 'AI output could not be parsed').slice(0, 500)\n}};"
      },
      "id": "018c2451-f124-423f-8e2f-212ee624df9b",
      "name": "Parse AI JSON",
      "type": "n8n-nodes-base.code",
      "typeVersion": 2,
      "position": [
        2100,
        220
      ]
    },
    {
      "parameters": {
        "rules": {
          "values": [
            {
              "conditions": {
                "options": {
                  "caseSensitive": true,
                  "leftValue": "",
                  "typeValidation": "strict",
                  "version": 2
                },
                "conditions": [
                  {
                    "id": "9c2a22de-6c4d-40d7-a2e5-288ff9d786f7",
                    "leftValue": "={{ $json.risk_level }}",
                    "rightValue": "low",
                    "operator": {
                      "type": "string",
                      "operation": "equals"
                    }
                  }
                ],
                "combinator": "and"
              },
              "renameOutput": true,
              "outputKey": "low"
            },
            {
              "conditions": {
                "options": {
                  "caseSensitive": true,
                  "leftValue": "",
                  "typeValidation": "strict",
                  "version": 2
                },
                "conditions": [
                  {
                    "id": "ba0194b7-68d3-40c6-8e59-9549824863c0",
                    "leftValue": "={{ $json.risk_level }}",
                    "rightValue": "medium",
                    "operator": {
                      "type": "string",
                      "operation": "equals"
                    }
                  }
                ],
                "combinator": "and"
              },
              "renameOutput": true,
              "outputKey": "medium"
            },
            {
              "conditions": {
                "options": {
                  "caseSensitive": true,
                  "leftValue": "",
                  "typeValidation": "strict",
                  "version": 2
                },
                "conditions": [
                  {
                    "id": "008671ad-f7b3-4130-9644-08f0154d67cd",
                    "leftValue": "={{ $json.risk_level }}",
                    "rightValue": "high",
                    "operator": {
                      "type": "string",
                      "operation": "equals"
                    }
                  }
                ],
                "combinator": "and"
              },
              "renameOutput": true,
              "outputKey": "high"
            }
          ]
        },
        "options": {}
      },
      "id": "d17f9b4a-af60-42c6-a0dd-0d95bcc70987",
      "name": "Switch",
      "type": "n8n-nodes-base.switch",
      "typeVersion": 3,
      "position": [
        2320,
        220
      ]
    },
    {
      "parameters": {
        "select": "channel",
        "channelId": {
          "__rl": true,
          "value": "phishing-alerts",
          "mode": "name"
        },
        "text": ":warning: *{{ $json.risk_level.toUpperCase() }} risk email*\nFrom: {{ $json.from }}\nSubject: {{ $json.subject }}\nReason: {{ $json.reason }}\nVirusTotal: {{ $json.vt_summary }}",
        "otherOptions": {}
      },
      "id": "775452a8-8457-4926-a7f1-b805c08a2721",
      "name": "Slack Alert",
      "type": "n8n-nodes-base.slack",
      "typeVersion": 2.3,
      "position": [
        2600,
        320
      ],
      "credentials": {
        "slackApi": {
          "id": "REPLACE_SLACK",
          "name": "Slack account"
        }
      },
      "onError": "continueRegularOutput"
    },
    {
      "parameters": {
        "fromEmail": "YOUR_EMAIL@gmail.com",
        "toEmail": "YOUR_EMAIL@gmail.com",
        "subject": "=PHISHING ALERT: {{ $json.subject }}",
        "emailFormat": "text",
        "text": "=High-risk email detected.\nFrom: {{ $json.from }}\nSubject: {{ $json.subject }}\nReason: {{ $json.reason }}\nVirusTotal: {{ $json.vt_summary }}",
        "options": {}
      },
      "id": "04ff9a36-f909-42cc-bedc-3c125433de07",
      "name": "Send Warning Email",
      "type": "n8n-nodes-base.emailSend",
      "typeVersion": 2.1,
      "position": [
        2840,
        420
      ],
      "credentials": {
        "smtp": {
          "id": "REPLACE_SMTP",
          "name": "SMTP account"
        }
      },
      "onError": "continueRegularOutput"
    },
    {
      "parameters": {
        "operation": "insert",
        "schema": {
          "__rl": true,
          "value": "public",
          "mode": "list",
          "cachedResultName": "public"
        },
        "table": {
          "__rl": true,
          "value": "phishing_logs",
          "mode": "name"
        },
        "columns": {
          "mappingMode": "defineBelow",
          "value": {
            "sender": "={{ $json.from }}",
            "subject": "={{ $json.subject }}",
            "risk_level": "={{ $json.risk_level }}",
            "reason": "={{ $json.reason }}"
          },
          "matchingColumns": [],
          "schema": [
            {
              "id": "sender",
              "displayName": "sender",
              "required": false,
              "defaultMatch": false,
              "display": true,
              "type": "string",
              "canBeUsedToMatch": true
            },
            {
              "id": "subject",
              "displayName": "subject",
              "required": false,
              "defaultMatch": false,
              "display": true,
              "type": "string",
              "canBeUsedToMatch": true
            },
            {
              "id": "risk_level",
              "displayName": "risk_level",
              "required": false,
              "defaultMatch": false,
              "display": true,
              "type": "string",
              "canBeUsedToMatch": true
            },
            {
              "id": "reason",
              "displayName": "reason",
              "required": false,
              "defaultMatch": false,
              "display": true,
              "type": "string",
              "canBeUsedToMatch": true
            }
          ]
        },
        "options": {}
      },
      "id": "f31b190f-80e3-4676-980e-375ce0188af0",
      "name": "Log to Postgres",
      "type": "n8n-nodes-base.postgres",
      "typeVersion": 2.5,
      "position": [
        2600,
        120
      ],
      "credentials": {
        "postgres": {
          "id": "REPLACE_PG",
          "name": "Postgres account"
        }
      }
    },
    {
      "parameters": {
        "schemaType": "manual",
        "inputSchema": "{\"type\": \"object\", \"properties\": {\"risk_level\": {\"type\": \"string\", \"enum\": [\"low\", \"medium\", \"high\"]}, \"score\": {\"type\": \"number\"}, \"reason\": {\"type\": \"string\"}}, \"required\": [\"risk_level\", \"reason\"]}"
      },
      "id": "d5b18450-4026-4197-80d9-647246232c45",
      "name": "Structured Output Parser",
      "type": "@n8n/n8n-nodes-langchain.outputParserStructured",
      "typeVersion": 1.2,
      "position": [
        1420,
        440
      ]
    }
  ],
  "connections": {
    "When clicking Execute workflow": {
      "main": [
        [
          {
            "node": "Mock Emails",
            "type": "main",
            "index": 0
          }
        ]
      ]
    },
    "Mock Emails": {
      "main": [
        [
          {
            "node": "Normalize Email",
            "type": "main",
            "index": 0
          }
        ]
      ]
    },
    "Normalize Email": {
      "main": [
        [
          {
            "node": "Has URL?",
            "type": "main",
            "index": 0
          }
        ]
      ]
    },
    "Has URL?": {
      "main": [
        [
          {
            "node": "VT Submit URL",
            "type": "main",
            "index": 0
          }
        ],
        [
          {
            "node": "Prep Context",
            "type": "main",
            "index": 0
          }
        ]
      ]
    },
    "VT Submit URL": {
      "main": [
        [
          {
            "node": "Wait 15s",
            "type": "main",
            "index": 0
          }
        ]
      ]
    },
    "Wait 15s": {
      "main": [
        [
          {
            "node": "VT Get Result",
            "type": "main",
            "index": 0
          }
        ]
      ]
    },
    "VT Get Result": {
      "main": [
        [
          {
            "node": "Prep Context",
            "type": "main",
            "index": 0
          }
        ]
      ]
    },
    "Prep Context": {
      "main": [
        [
          {
            "node": "Analyze Email",
            "type": "main",
            "index": 0
          }
        ]
      ]
    },
    "Google Gemini Chat Model": {
      "ai_languageModel": [
        [
          {
            "node": "Analyze Email",
            "type": "ai_languageModel",
            "index": 0
          }
        ]
      ]
    },
    "Parse AI JSON": {
      "main": [
        [
          {
            "node": "Switch",
            "type": "main",
            "index": 0
          }
        ]
      ]
    },
    "Switch": {
      "main": [
        [
          {
            "node": "Log to Postgres",
            "type": "main",
            "index": 0
          }
        ],
        [
          {
            "node": "Slack Alert",
            "type": "main",
            "index": 0
          },
          {
            "node": "Log to Postgres",
            "type": "main",
            "index": 0
          }
        ],
        [
          {
            "node": "Slack Alert",
            "type": "main",
            "index": 0
          },
          {
            "node": "Send Warning Email",
            "type": "main",
            "index": 0
          },
          {
            "node": "Log to Postgres",
            "type": "main",
            "index": 0
          }
        ]
      ]
    },
    "Analyze Email": {
      "main": [
        [
          {
            "node": "Parse AI JSON",
            "type": "main",
            "index": 0
          }
        ]
      ]
    },
    "Structured Output Parser": {
      "ai_outputParser": [
        [
          {
            "node": "Analyze Email",
            "type": "ai_outputParser",
            "index": 0
          }
        ]
      ]
    }
  },
  "pinData": {},
  "active": false,
  "settings": {
    "executionOrder": "v1"
  },
  "tags": []
}
````
