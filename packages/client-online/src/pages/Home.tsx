import React from "react";
import { useNavigate } from "react-router-dom";
import { useI18n } from "@/lib/i18n";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";

export default function Home() {
  const { t } = useI18n();
  const nav = useNavigate();

  return (
    <div className="space-y-6">
      <div className="text-center space-y-2">
        <h2 className="text-2xl font-bold">{t("homeTitle")}</h2>
        <p className="text-muted-foreground">{t("homeSubtitle")}</p>
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>{t("createCardTitle")}</CardTitle>
            <CardDescription>{t("createCardDesc")}</CardDescription>
          </CardHeader>
          <CardContent>
            <Button className="w-full" onClick={() => nav("/create")}>
              {t("goToCreate")}
            </Button>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>{t("broadcastCardTitle")}</CardTitle>
            <CardDescription>{t("broadcastCardDesc")}</CardDescription>
          </CardHeader>
          <CardContent>
            <Button className="w-full" variant="secondary" onClick={() => nav("/broadcast")}>
              {t("goToBroadcast")}
            </Button>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
