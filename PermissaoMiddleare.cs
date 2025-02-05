using LibLogin;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using System.Security.Claims;

public class PermissaoAttribute : TypeFilterAttribute
{
    public PermissaoAttribute() : base(typeof(PermissaoMiddlewareFilter))
    {
    }

    private class PermissaoMiddlewareFilter : IAsyncActionFilter
    {
        public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
        {
            var rota = context.HttpContext.Request.Path.Value;
            //ip direto conexão
            string ip = context.HttpContext.Request.Headers["X-Forwarded-For"].FirstOrDefault()
                ?? context.HttpContext.Connection.RemoteIpAddress?.ToString();

            // Verificar se a rota é de um arquivo
            if (IsFileRequest(rota))
            {
                await next();
                return;
            }

            // Verificar se o usuário está autenticado
            if (!context.HttpContext.Request.Headers.ContainsKey("token"))
            {
                context.Result = new UnauthorizedResult();
                return;
            }


            string token = context.HttpContext.Request.Headers["token"];
            var service = ServiceStatic.GetService();
            var autorizado = await service.Autenticado<dynamic>(token, context.HttpContext);
            if (!autorizado)
            {
                context.Result = new UnauthorizedResult();
                return;
            }

            //depois verificar se o usuário tem permissão para acessar a rota
            var auth = await service.Autorizado(rota, token);

            if (!auth)
            {
                context.Result = new UnauthorizedResult();
                return;
            }

            await next();
        }

        private bool IsFileRequest(string path)
        {
            string[] fileExtensions = { ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot" };
            return fileExtensions.Any(ext => path.EndsWith(ext, System.StringComparison.OrdinalIgnoreCase));
        }
    }
}
