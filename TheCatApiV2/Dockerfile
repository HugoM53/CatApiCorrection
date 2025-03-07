#See https://aka.ms/customizecontainer to learn how to customize your debug container and how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:7.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:7.0 AS build

COPY ["TheCatApiV2.csproj", "TheCatApiV2/"]
RUN dotnet restore "TheCatApiV2/TheCatApiV2.csproj"
COPY . .
WORKDIR "/TheCatApiV2"
RUN dotnet build "TheCatApiV2.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "TheCatApiV2.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .


RUN dotnet ef database update --context DatabaseContext --no-build -c Release -o /app/publish

ENTRYPOINT ["dotnet", "TheCatApiV2.dll"]