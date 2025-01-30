using LibLogin;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using System.Security.Claims;
using testedxdd;

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

            // Verificar se a rota é de um arquivo
            if (IsFileRequest(rota))
            {
                await next();
                return;
            }

            // Verificar se o usuário está autenticado
            if(!context.HttpContext.Request.Headers.ContainsKey("token"))
            {
                context.Result = new UnauthorizedResult();
                return;
            }


            string token = context.HttpContext.Request.Headers["token"];
            var service = new Service();
            var autorizado = await service.Autorizado<dynamic>(token);
            if(!autorizado)
            {
                context.Result = new UnauthorizedResult();
                return;
            }

            //depois verificar se o usuário tem permissão para acessar a rota


            await next();
        }

        private bool IsFileRequest(string path)
        {
            string[] fileExtensions = { ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot" };
            return fileExtensions.Any(ext => path.EndsWith(ext, System.StringComparison.OrdinalIgnoreCase));
        }
    }
}
