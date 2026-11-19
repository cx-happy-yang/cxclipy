"""
File extensions of the languages and frameworks supported by Checkmarx products.

CXSAST_SUPPORTED_FILE_EXTENSIONS is the union of the "File extensions" column of
the CxSAST supported languages and frameworks table, deduplicated.
CXONE_ADDITIONAL_FILE_EXTENSIONS holds the extra extensions CxOne zips should
include on top of the CxSAST-supported ones.
"""

# All file extensions listed in the CxSAST supported languages and frameworks table.
CXSAST_SUPPORTED_FILE_EXTENSIONS = [
    '-meta.xml',
    '.ac', '.am', '.apex', '.apexp', '.apxc', '.app', '.asax', '.ascx', '.asp', '.aspx',
    '.bas', '.c', '.c++', '.cbl', '.cc', '.cgi', '.cls', '.cmake', '.cmp', '.cob',
    '.component', '.conf', '.config', '.cpp', '.cpy', '.cs', '.cshtml', '.ctl', '.ctp', '.csv',
    '.cxx', '.dart', '.dsr', '.dspf', '.ec', '.eco', '.env', '.erb', '.evt', '.frm',
    '.ftl', '.go', '.gradle', '.groovy', '.gsh', '.gsp', '.gtl', '.gvy', '.gy', '.h',
    '.h++', '.handlebars', '.hbs', '.hh', '.hpp', '.htm', '.html', '.hxx', '.inc', '.ini',
    '.jade', '.java', '.js', '.jsf', '.json', '.jsx', '.jsp', '.jspdsbld', '.jspf', '.kt', '.kts',
    '.latex', '.lock', '.lua', '.m', '.master', '.mf', '.mod', '.mustache', '.object', '.page',
    '.pc', '.pck', '.pco', '.ph', '.php', '.php3', '.php4', '.php5', '.phtm', '.phtml',
    '.pkb', '.pkh', '.pks', '.pl', '.plist', '.pls', '.plx', '.pm', '.pro', '.properties',
    '.psgi', '.pug', '.py', '.rb', '.report', '.rhtml', '.rjs', '.rpg', '.rpg38', '.rpgle',
    '.rs', '.rxml', '.scala', '.sqb', '.sql', '.sqlrpg', '.sqlrpgle', '.swift', '.tag', '.tex',
    '.tgr', '.tld', '.toml', '.tpl', '.trigger', '.ts', '.tsx', '.twig', '.txt', '.vb',
    '.vbp', '.vbs', '.vm', '.vue', '.wod', '.workflow', '.xaml', '.xhtml', '.xib', '.xml',
    '.xsaccess', '.xsapp', '.xsjs', '.xsjslib', '.yaml', '.yml'
]

# Extensions used by CxOne in addition to the CxSAST-supported ones.
CXONE_ADDITIONAL_FILE_EXTENSIONS = [
    '.cfg', '.configurations', '.csproj', '.env_cxsca-container-build-args', '.npmrc', '.private',
    '.resolved', '.rev', '.sbt', '.snapshot', '.sum', '.target', '.testtarget', '.vbproj', '.yarnrc'
]
