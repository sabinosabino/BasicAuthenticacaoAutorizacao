using BaseDapper;
using System.Data.SQLite;
using Dapper;
using System.Data;


namespace LibLogin
{
    public class Service
    {
        private DbContext _db;
        private IDbConnection _conn;

        private bool _controlaIp;
        private int timeToken = 1;
        public Service(bool controlaIp = false)
        {
            _db = new BaseDapper.DbContext(new SQLiteConnection("Data Source=session.db;"));
            _controlaIp = controlaIp;
        }
        public void Init()
        {
            ExecInstrucoes();
        }
        private async void ExecInstrucoes()
        {
            CriarBancoSeNaoExistir();
            await CriarTabelas();
        }
        private void CriarBancoSeNaoExistir()
        {
            try
            {
                if (!File.Exists("session.db"))
                    SQLiteConnection.CreateFile("session.db");
            }
            catch (Exception)
            {
                throw;
            }
        }
        private async Task CriarTabelas()
        {
            #region Autenticacao
            string sql = @"CREATE TABLE IF NOT EXISTS Autenticacao (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                UsuarioId TEXT NOT NULL,
                Usuario TEXT NOT NULL,
                Nome TEXT NOT NULL,
                Email TEXT NOT NULL,
                GrupoId TEXT NOT NULL,
                EmpresaId TEXT NOT NULL,
                DataHora TEXT NOT NULL,
                Token TEXT NOT NULL,
                Validade TEXT NOT NULL
            )";

            await _db.GetConnection().ExecuteAsync(sql);

            #endregion

            #region Grupo
            sql = @"CREATE TABLE IF NOT EXISTS Grupo (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                Nome TEXT NOT NULL,
                EmpresaId TEXT NOT NULL
            )";

            await _db.GetConnection().ExecuteAsync(sql);

            #endregion

            #region Rotas
            sql = @"CREATE TABLE IF NOT EXISTS Rotas (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                Nome TEXT NOT NULL,
                EmpresaId TEXT NOT NULL
            )";

            await _db.GetConnection().ExecuteAsync(sql);

            #endregion

            #region rotas
            sql = @"DROP TABLE IF EXISTS Rotas";

            await _db.GetConnection().ExecuteAsync(sql);

            sql = @"CREATE TABLE IF NOT EXISTS RotasAcessa (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                Nome TEXT NOT NULL,
                EmpresaId TEXT NOT NULL
            )";

            await _db.GetConnection().ExecuteAsync(sql);
            #endregion

            #region Logs

            sql = @"CREATE TABLE IF NOT EXISTS Logs (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                UsuarioId TEXT NOT NULL,
                Usuario TEXT NOT NULL,
                Nome TEXT NOT NULL,
                Email TEXT NOT NULL,
                GrupoId TEXT NOT NULL,
                EmpresaId TEXT NOT NULL,
                DataHora TEXT NOT NULL,
                Token TEXT NOT NULL,
                Validade TEXT NOT NULL
            )";


            await _db.GetConnection().ExecuteAsync(sql);


            //criar trigger para log
            sql = @"CREATE TRIGGER IF NOT EXISTS log_insert AFTER INSERT ON Autenticacao
            BEGIN
                INSERT INTO Logs (UsuarioId, Usuario, Nome, Email, GrupoId, EmpresaId, DataHora, Token, Validade)
                VALUES (new.UsuarioId, new.Usuario, new.Nome, new.Email, new.GrupoId, new.EmpresaId, new.DataHora, new.Token, new.Validade);
            END;";
            await _db.GetConnection().ExecuteAsync(sql);
            #endregion

            #region alteracaoAutencacao
            sql = @"
                SELECT COUNT(*) FROM pragma_table_info('Autenticacao') 
                WHERE name = 'Ip';
            ";

            if (await _db.GetConnection().QuerySingleAsync<int>(sql) == 0)
            {
                await _db.GetConnection().ExecuteAsync("ALTER TABLE Autenticacao ADD COLUMN Ip TEXT;");
            }

            #endregion
        }
        public async Task<T> Registrar<T>(string id, string usuarioId, string usuario, string nome, string email, string grupoId, string empresaId, HttpContext context)
        {
            string ip = context.Request.Headers["X-Forwarded-For"].FirstOrDefault()
                    ?? context.Connection.RemoteIpAddress?.ToString();
            if (!_controlaIp)
                ip = "";

            var user = new
            {
                UsuarioId = usuarioId,
                Usuario = usuario,
                Nome = nome,
                Email = email,
                GrupoId = grupoId,
                EmpresaId = empresaId,
                DataHora = DateTime.Now,
                Token = Guid.NewGuid().ToString(),
                Validade = DateTime.Now.AddHours(timeToken),
                Ip = ip
            };
            var list = await _db.GetConnection().QueryAsync<T>("SELECT * FROM Autenticacao WHERE UsuarioId = @UsuarioId and EmpresaId=@EmpresaId", new { user.UsuarioId, user.EmpresaId });
            if (list.Count() > 0)
                await _db.GetConnection().ExecuteAsync("Delete from Autenticacao WHERE UsuarioId = @UsuarioId and EmpresaId=@EmpresaId", new { user.UsuarioId, user.EmpresaId });

            await _db.GetConnection().ExecuteAsync("INSERT INTO Autenticacao (UsuarioId, Usuario, Nome, Email, GrupoId, EmpresaId, DataHora, Token, Validade,Ip) VALUES (@UsuarioId, @Usuario, @Nome, @Email, @GrupoId, @EmpresaId, @DataHora, @Token, @Validade,@Ip)", user);

            return await _db.GetConnection().QueryFirstAsync<T>("SELECT * FROM Autenticacao Where Id=(SELECT MAX(Id) FROM Autenticacao)");
        }

        public async Task<bool> Autorizado<T>(string token, HttpContext context)
        {
            string ip = context.Request.Headers["X-Forwarded-For"].FirstOrDefault()
                    ?? context.Connection.RemoteIpAddress?.ToString();

            if (!_controlaIp)
                ip = "";

            var m = await _db.GetConnection().QueryFirstOrDefaultAsync<T>("SELECT * FROM Autenticacao WHERE Ip=@Ip and Token = @Token And Validade>@Data", new { Token = token, Data = DateTime.Now, Ip = ip });

            if (m != null)
                return true;
            return false;
        }
        public async Task<dynamic> RefreshToken(string token, HttpContext context)
        {

            string ip = context.Request.Headers["X-Forwarded-For"].FirstOrDefault()
                ?? context.Connection.RemoteIpAddress?.ToString();

            if (!_controlaIp)
                ip = "";

            var m = await _db.GetConnection().QueryFirstOrDefaultAsync("SELECT * FROM Autenticacao WHERE Token = @Token and Ip=@Ip", new { Token = token, Ip = ip });
            var user = new
            {
                UsuarioId = m.UsuarioId,
                Usuario = m.Usuario,
                Nome = m.Nome,
                Email = m.Email,
                GrupoId = m.GrupoId,
                EmpresaId = m.EmpresaId,
                DataHora = DateTime.Now,
                Token = Guid.NewGuid().ToString(),
                Validade = DateTime.Now.AddHours(timeToken),
                ip = ip
            };
            await _db.GetConnection().ExecuteAsync("Delete from Autenticacao WHERE Token = @Token", new { Token = token });
            await _db.GetConnection().ExecuteAsync("INSERT INTO Autenticacao (UsuarioId, Usuario, Nome, Email, GrupoId, EmpresaId, DataHora, Token, Validade,Ip) VALUES (@UsuarioId, @Usuario, @Nome, @Email, @GrupoId, @EmpresaId, @DataHora, @Token, @Validade,@Ip)", user);
            return new { token = user.Token, Validade = user.Validade };
        }

        public async Task Revogar(string token)
        {
            await _db.GetConnection().ExecuteAsync("Delete from Autenticacao WHERE Token = @Token", new { Token = token });
        }
    }

    public class UserRegister
    {
        public string UsuarioId { get; set; }
        public string Usuario { get; set; }
        public string Nome { get; set; }
        public string Email { get; set; }
        public int GrupoId { get; set; }
        public int EmpresaId { get; set; }
        public DateTime DataHora { get; set; } = DateTime.Now;
        public string Token { get; set; } = Guid.NewGuid().ToString();
        public DateTime Validade { get; set; }
        public string Ip { get; set; }

        public UserRegister()
        {
            
        }
        public UserRegister(string usuarioId, string usuario, string nome, string email, int grupoId, int empresaId, int timeToken, string ip)
        {
            UsuarioId = usuarioId;
            Usuario = usuario;
            Nome = nome;
            Email = email;
            GrupoId = grupoId;
            EmpresaId = empresaId;
            Validade = DateTime.Now.AddHours(timeToken);
            Ip = ip;
        }
    }

    public class ServiceStatic{
            private static Service service;
            public static Service GetService(){
                if(service==null)
                    return new Service(true);
                return service;
            }
        }
}
