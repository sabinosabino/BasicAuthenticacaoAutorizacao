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

        private int timeToken=1;
        public Service()
        {
            _db = new BaseDapper.DbContext(new SQLiteConnection("Data Source=session.db;"));
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
        }
        public async Task<T> Registrar<T>(string id, string usuarioId, string usuario, string nome, string email, string grupoId, string empresaId)
        {
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
                Validade = DateTime.Now.AddHours(timeToken)
            };
            var list = await _db.GetConnection().QueryAsync<T>("SELECT * FROM Autenticacao WHERE UsuarioId = @UsuarioId and EmpresaId=@EmpresaId", new { user.UsuarioId, user.EmpresaId });
            if (list.Count() > 0)
                await _db.GetConnection().ExecuteAsync("Delete from Autenticacao WHERE UsuarioId = @UsuarioId and EmpresaId=@EmpresaId", new { user.UsuarioId, user.EmpresaId });

            await _db.GetConnection().ExecuteAsync("INSERT INTO Autenticacao (UsuarioId, Usuario, Nome, Email, GrupoId, EmpresaId, DataHora, Token, Validade) VALUES (@UsuarioId, @Usuario, @Nome, @Email, @GrupoId, @EmpresaId, @DataHora, @Token, @Validade)", user);

            return await _db.GetConnection().QueryFirstAsync<T>("SELECT * FROM Autenticacao Where Id=(SELECT MAX(Id) FROM Autenticacao)");
        }

        public async Task<bool> Autorizado<T>(string token)
        {

            var m = await _db.GetConnection().QueryFirstOrDefaultAsync<T>("SELECT * FROM Autenticacao WHERE Token = @Token And Validade>@Data", new { Token = token, Data=DateTime.Now });

            if(m!=null)
                return true;
            return false;
        }
        public async Task<dynamic> RefreshToken(string token){
            var m = await _db.GetConnection().QueryFirstOrDefaultAsync("SELECT * FROM Autenticacao WHERE Token = @Token", new { Token = token });
            var user = new {
                 UsuarioId = m.UsuarioId,
                Usuario = m.Usuario,
                Nome = m.Nome,
                Email = m.Email,
                GrupoId = m.GrupoId,
                EmpresaId = m.EmpresaId,
                DataHora = DateTime.Now,
                Token = Guid.NewGuid().ToString(),
                Validade = DateTime.Now.AddHours(timeToken)
            };
            await _db.GetConnection().ExecuteAsync("Delete from Autenticacao WHERE Token = @Token", new { Token = token });
            await _db.GetConnection().ExecuteAsync("INSERT INTO Autenticacao (UsuarioId, Usuario, Nome, Email, GrupoId, EmpresaId, DataHora, Token, Validade) VALUES (@UsuarioId, @Usuario, @Nome, @Email, @GrupoId, @EmpresaId, @DataHora, @Token, @Validade)", user);
            return new{token=user.Token,Validade=user.Validade};
        }

        public async Task Revogar(string token)
        {
            await _db.GetConnection().ExecuteAsync("Delete from Autenticacao WHERE Token = @Token", new { Token = token });
        }
    }

    
}
