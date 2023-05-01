require('dotenv').config();
const express = require('express')
const app = express()
const port = process.env.PORT || 3001
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const saltRounds = 10;
const util = require('util');
const cors = require('cors');

app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: true }));

const connection = mysql.createConnection(process.env.DATABASE_URL);
connection.connect()

const pool = mysql.createPool(process.env.DATABASE_URL);
const queryAsync = util.promisify(pool.query).bind(pool);


function errorHandler(err, req, res, next) {
  // Check if response has already been sent
  if (res.headersSent) {
    return next(err);
  }
  
  // Set status code and send error message
  res.status(500);
  res.send('An error occurred: ' + err.message);
}

// Add error handler to app
app.use(errorHandler);

// Middleware to authenticate requests
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decodedToken) => {
    if (err) return res.sendStatus(403);
    req.authorId = decodedToken.username;
    next();
  });
};

app.get('/ok', (req, res) => {
  res.status(200).send('OK');
});


app.post('/admin/code', authenticateToken, (req, res) => {
  const adminId = req.authorId;
  if (adminId === "nim") {
    const { username } = req.body;
    const code = generateRegistrationCode(username);
    res.send(code);
  } else {
    res.status(403).send('Forbidden');
  }
});

function generateRegistrationCode(username) {
  const code = process.env.REGISTRATION_CODE + username;
  return bcrypt.hashSync(code, saltRounds);
}

app.post('/register', (req, res) => {
  const { code, password, username } = req.body;
  
  if (code !== process.env.REGISTRATION_CODE) {
    return res.status(400).send('Invalid registration code');
  }
  // Check that the user does not already exist in the database
  connection.query('SELECT * FROM Authors WHERE username = ?', [username], function (error, results, fields) {
    if (error) throw error;
    if (results.length > 0) {
      return res.status(409).send('User already exists');
    }

    // Hash the password
    bcrypt.hash(password, 10, (err, hashedPassword) => {
      if (err) throw err;

      // Store the new user in the database
      connection.query('INSERT INTO Authors SET ?', { username: username, password: hashedPassword }, function (error, results, fields) {
        if (error) throw error;

        res.status(201).send('User created successfully');
      });
    });
  });
});

app.post('/auth', (req, res) => {
  const { username, password } = req.body;
  connection.query('SELECT * FROM Authors WHERE username = ?', [username], function (error, results, fields) {
    if (error) throw error;
    if (results.length === 0) {
      return res.status(401).send('Invalid username or password');
    }
  
    const hashedPassword = results[0].password;
    bcrypt.compare(password, hashedPassword, function (err, passwordMatch) {
      if (passwordMatch) {
        const accessToken = jwt.sign({ username: results[0].username }, process.env.ACCESS_TOKEN_SECRET);
        res.json({ accessToken });
      } else {
        res.status(401).send('Invalid username or password');
      }
    });
  });
});


app.get('/mods', authenticateToken, (req, res) => {
  const username = req.authorId;

  connection.query('SELECT * FROM Mods WHERE modAuthor = ?', [username], (err, rows, fields) => {
    if (err) {
      console.error(err);
      res.status(500).send('Internal Server Error');
    } else {
      res.send(rows);
    }
  });
});

app.get('/mods/:modId', authenticateToken, (req, res) => {
  const modId = req.params.modId;
  
  // retrieve the mod from the database
  connection.query('SELECT * FROM Mods WHERE modId = ?', [modId], (err, results) => {
    if (err) {
      console.log(err);
      return res.status(500).send('Error retrieving mod');
    }

    // check if mod exists
    if (results.length === 0) {

      return res.status(404).send('Mod not found');
    }

    // return mod information
    const mod = results[0];
    return res.json(mod);
  });
});

app.post('/mods', authenticateToken, async (req, res) => {
  const { modId, modName, modDescription, modVersion, modReleaseDate, modTags } = req.body;
  const authorId = req.authorId;

  const query = 'INSERT INTO Mods (modId, modName, modDescription, modAuthor, modVersion, modReleaseDate,  modTags) VALUES (?, ?, ?, ?, ?, ?, ?)';

  if (modId && modName) {
    connection.query(
      query,
      [modId, modName, modDescription || null, authorId, modVersion || null, modReleaseDate || null, modTags || null],
      (error, results, fields) => {
        if (error) {
          console.error(error);
          res.status(500).send('Error creating new mod');
        } else {
          res.status(201).json(results);
        }
      }
    );
  } else {
    res.status(400).send('modId and modName are required');
  }
});

app.put('/mods/:modId', authenticateToken, async (req, res) => {
  const modId = req.params.modId;
  const authorId = req.authorId;
  const { modName, modDescription, modVersion, modTags } = req.body;

  const query = 'UPDATE Mods SET modName = ?, modDescription = ?, modVersion = ?, modTags = ? WHERE modId = ? AND modAuthor = ?';

  connection.query(
    query,
    [modName || null, modDescription || null, modVersion || null, modTags || null, modId, authorId],
    (error, results, fields) => {
      console.log(fields);
      if (error) {
        console.error(results);
        res.status(500).send('Error updating mod');
      } else if (results.affectedRows === 0) {
        res.status(404).send('Mod not found');
      } else {
        res.status(200).json(results);
      }
    }
  );
});

app.delete('/mods/:modId', authenticateToken, (req, res) => {
  const username = req.authorId;
  const modId = req.params.modId;

  connection.query('SELECT * FROM Mods WHERE modAuthor = ? AND modId = ?', [username, modId], (err, rows, fields) => {
    if (err) {
      console.error(err);
      res.status(500).send('Internal Server Error');
    } else if (rows.length === 0) {
      res.status(404).send('Mod Not Found');
    } else {
      connection.query('DELETE FROM Mods WHERE modAuthor = ? AND modId = ?', [username, modId], (err, result) => {
        if (err) {
          console.error(err);
          res.status(500).send('Internal Server Error');
        } else {
          res.status(204).send();
        }
      });
    }
  });
});

app.get('/mods/:modId/versions', authenticateToken, async (req, res) => {
  const authorId = req.authorId;
  const modId = req.params.modId;

  try {
    // Check if the mod belongs to the current author
    const modResults = await queryAsync('SELECT modAuthor FROM Mods WHERE modId = ?', [modId]);

    if (modResults.length === 0 || modResults[0].modAuthor !== authorId) {
      return res.status(404).json({ error: 'Mod not found or forbidden' });
    }

    // Get all versions of the mod
    const versionResults = await queryAsync('SELECT modVersionId, modID, versionNumber, releaseDate, changelog FROM ModVersions WHERE modID = ?', [modId]);


    const modVersions = versionResults && versionResults.length > 0 ? versionResults.map((row) => {
      return {
        modVersionId: row.modVersionId,
        modId: row.modID,
        versionNumber: row.versionNumber,
        releaseDate: row.releaseDate,
        changelog: row.changelog
      };
    }) : [];

    res.json(modVersions);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/mods/:modId/versions/:versionId', authenticateToken, async (req, res) => {
  const authorId = req.authorId;
  const modId = req.params.modId;
  const versionId = req.params.versionId;

  try {
    // Check if the mod belongs to the current author
    const modResults = await queryAsync('SELECT modAuthor FROM Mods WHERE modId = ?', [modId]);

    if (modResults.length === 0 || modResults[0].modAuthor !== authorId) {
      return res.status(404).json({ error: 'Mod not found or forbidden' });
    }

    // Get the specific version of the mod
    const versionResults = await queryAsync('SELECT modVersionId, modID, versionNumber, releaseDate, changelog FROM ModVersions WHERE modID = ? AND modVersionId = ?', [modId, versionId]);

    if (versionResults.length === 0) {
      return res.status(404).json({ error: 'Version not found' });
    }

    const modVersion = {
      modVersionId: versionResults[0].modVersionId,
      modId: versionResults[0].modID,
      versionNumber: versionResults[0].versionNumber,
      releaseDate: versionResults[0].releaseDate,
      changelog: versionResults[0].changelog
    };

    res.json(modVersion);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/mods/:modId/versions', authenticateToken, async (req, res) => {
  const { modId, versionNumber, releaseDate, changelog} = req.body;
  const authorId = req.authorId;

  try {
    // Check if the mod belongs to the current author
    const modResults = await queryAsync('SELECT modAuthor FROM Mods WHERE modId = ?', [modId]);

    if (modResults.length === 0 || modResults[0].modAuthor !== authorId) {
      return res.status(404).json({ error: 'Mod not found or forbidden' });
    }

    // Create the specific version of the mod
    const query = await queryAsync('INSERT INTO ModVersions (modId, versionNumber, releaseDate, changelog) VALUES (?, ?, ?, ?)', [ modId, versionNumber || null, releaseDate || null, changelog || null]);

    res.json("Version created");
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/mods/:modId/versions/:versionId', authenticateToken, async (req, res) => {
  const modID = req.params.modId;
  const modVersionId = req.params.versionId;
  const authorId = req.authorId;

  try {
    // Check if the mod belongs to the current author
    const modResults = await queryAsync('SELECT modAuthor FROM Mods WHERE modID = ?', [modID]);

    if (modResults.length === 0 || modResults[0].modAuthor !== authorId) {
      return res.status(404).json({ error: 'Mod not found or forbidden' });
    }

    // Delete the specific version of the mod
    const query = await queryAsync('DELETE FROM ModVersions WHERE modVersionId = ?', [modVersionId]);

    res.json("Version deleted");
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /mods/:modId/versions/:versionId/files - Returns a list of all files for a specific version of a mod belonging to the current author.
// fileID, modVersionID, fileType, fileSize, fileURL, uploadDate
app.get('/mods/:modId/versions/:versionId/files', authenticateToken, async (req, res) => {
  const authorId = req.authorId;
  const modId = req.params.modId;
  const versionId = req.params.versionId;

  try {
    // Check if the mod belongs to the current author
    const modResults = await queryAsync('SELECT modAuthor FROM Mods WHERE modId = ?', [modId]);

    if (modResults.length === 0 || modResults[0].modAuthor !== authorId) {
      return res.status(404).json({ error: 'Mod not found or forbidden' });
    }

    // Get all files for the specific version of the mod
    const fileResults = await queryAsync('SELECT fileID, modVersionID, fileType, fileSize, fileURL, uploadDate FROM ModFiles WHERE modVersionID = ?', [versionId]);

    const modFiles = fileResults && fileResults.length > 0 ? fileResults.map((row) => {
      return {
        fileID: row.fileID,
        modVersionID: row.modVersionID,
        fileType: row.fileType,
        fileSize: row.fileSize,
        fileURL: row.fileURL,
        uploadDate: row.uploadDate
      };
    }) : [];

    res.json(modFiles);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /mods/:modId/versions/:versionId/files - Uploads a new file for a specific version of a mod belonging to the current author.
app.post('/mods/:modId/versions/:versionId/files', authenticateToken, async (req, res) => {
  const modId = req.params.modId;
  const modVersionID = req.params.versionId;
  const { fileType, fileSize, fileURL } = req.body;
  const authorId = req.authorId;

  try {
    // Check if the mod belongs to the current author
    const modResults = await queryAsync('SELECT modAuthor FROM Mods WHERE modID = ?', [modId]);

    if (modResults.length === 0 || modResults[0].modAuthor !== authorId) {
      return res.status(404).json({ error: 'Mod not found or forbidden' });
    }

    // Create the file for the specific version of the mod
    const query = await queryAsync('INSERT INTO ModFiles (modVersionID, fileType, fileSize, fileURL) VALUES (?, ?, ?, ?)', [modVersionID, fileType || null, fileSize || null, fileURL || null]);

    res.json("File created");
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// DELETE /mods/:modId/versions/:versionId/files/:fileId - Deletes a specific file for a specific version of a mod belonging to the current author.
app.delete('/mods/:modId/versions/:versionId/files/:fileId', authenticateToken, async (req, res) => {
  const modID = req.params.modId;
  const modVersionID = req.params.versionId;
  const fileID = req.params.fileId;
  const authorId = req.authorId;

  try {
    // Check if the mod belongs to the current author
    const modResults = await queryAsync('SELECT modAuthor FROM Mods WHERE modID = ?', [modID]);
    
    if (modResults.length === 0 || modResults[0].modAuthor !== authorId) {
      return res.status(404).json({ error: 'Mod not found or forbidden' });
    }

    // Delete the specific file for the specific version of the mod
    const query = await queryAsync('DELETE FROM ModFiles WHERE fileID = ?', [fileID]);

    res.json("File deleted");
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /mods/:modId/dependencies/:versionId - Returns a list of all dependencies for a specific version belonging to the current author.
// modVersionID, dependencyModID, maximumDependencyVersion, minimumDependencyVersion, dependencyType( required, optional, incompatible)
app.get('/mods/:modId/dependencies/:versionId', authenticateToken, async (req, res) => {
  const authorId = req.authorId;
  const modId = req.params.modId;
  const versionId = req.params.versionId;

  try {
    // Check if the mod belongs to the current author
    const modResults = await queryAsync('SELECT modAuthor FROM Mods WHERE modId = ?', [modId]);

    if (modResults.length === 0 || modResults[0].modAuthor !== authorId) {
      return res.status(404).json({ error: 'Mod not found or forbidden' });
    }

    // Get all dependencies for the specific version of the mod
    const dependencyResults = await queryAsync('SELECT modVersionID, dependencyModID, maximumDependencyVersion, minimumDependencyVersion, dependencyType FROM ModDependencies WHERE modVersionID = ?', [versionId]);

    const modDependencies = dependencyResults && dependencyResults.length > 0 ? dependencyResults.map((row) => {
      return {
        modVersionID: row.modVersionID,
        dependencyModID: row.dependencyModID,
        maximumDependencyVersion: row.maximumDependencyVersion,
        minimumDependencyVersion: row.minimumDependencyVersion,
        dependencyType: row.dependencyType
      };
    }) : [];

    res.json(modDependencies);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /mods/:modId/dependencies/:versionId - Adds a new dependency for a specific version belonging to the current author.
app.post('/mods/:modId/dependencies/:versionId', authenticateToken, async (req, res) => {
  const modId = req.params.modId;
  const modVersionID = req.params.versionId;
  const { dependencyModID, maximumDependencyVersion, minimumDependencyVersion, dependencyType } = req.body;
  const authorId = req.authorId;

  try {
    // Check if the mod belongs to the current author
    const modResults = await queryAsync('SELECT modAuthor FROM Mods WHERE modID = ?', [modId]);

    if (modResults.length === 0 || modResults[0].modAuthor !== authorId) {
      return res.status(404).json({ error: 'Mod not found or forbidden' });
    }

    // Create the dependency for the specific version of the mod
    const query = await queryAsync('INSERT INTO ModDependencies (modVersionID, dependencyModID, maximumDependencyVersion, minimumDependencyVersion, dependencyType) VALUES (?, ?, ?, ?, ?)', [modVersionID, dependencyModID || null, maximumDependencyVersion || null, minimumDependencyVersion || null, dependencyType || null]);

    res.json("Dependency created");
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// PUT /mods/:modId/dependencies/:versionId/:dependencyId - Updates the details of a specific dependency for a specific version belonging to the current author.
app.put('/mods/:modId/dependencies/:versionId/:dependencyId', authenticateToken, async (req, res) => {
  const modId = req.params.modId;
  const modVersionID = req.params.versionId;
  const dependencyID = req.params.dependencyId;
  const { dependencyModID, maximumDependencyVersion, minimumDependencyVersion, dependencyType } = req.body;
  const authorId = req.authorId;

  try {
    // Check if the mod belongs to the current author
    const modResults = await queryAsync('SELECT modAuthor FROM Mods WHERE modID = ?', [modId]);

    if (modResults.length === 0 || modResults[0].modAuthor !== authorId) {
      return res.status(404).json({ error: 'Mod not found or forbidden' });
    }

    // Update the dependency for the specific version of the mod
    const query = await queryAsync('UPDATE ModDependencies SET dependencyModID = ?, maximumDependencyVersion = ?, minimumDependencyVersion = ?, dependencyType = ? WHERE dependencyID = ?', [dependencyModID || null, maximumDependencyVersion || null, minimumDependencyVersion || null, dependencyType || null, dependencyID]);

    res.json("Dependency updated");
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// DELETE /mods/:modId/dependencies/:versionId/:dependencyId - Deletes a specific dependency for a specific version belonging to the current author.
app.delete('/mods/:modId/dependencies/:versionId/:dependencyId', authenticateToken, async (req, res) => {
  const modID = req.params.modId;
  const modVersionID = req.params.versionId;
  const dependencyID = req.params.dependencyId;
  const authorId = req.authorId;

  try {
    // Check if the mod belongs to the current author
    const modResults = await queryAsync('SELECT modAuthor FROM Mods WHERE modID = ?', [modID]);
    
    if (modResults.length === 0 || modResults[0].modAuthor !== authorId) {
      return res.status(404).json({ error: 'Mod not found or forbidden' });
    }

    // Delete the dependency for the specific version of the mod
    const query = await queryAsync('DELETE FROM ModDependencies WHERE dependencyID = ?', [dependencyID]);

    res.json("Dependency deleted");
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});




app.listen(port, () => {
  console.log(`API listening at http://localhost:${port}`)
})
